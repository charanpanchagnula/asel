# tests/test_surface.py
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from asel.surface import SurfaceDiscovery
from asel.models import SurfaceDiscoveryResult


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """Minimal Spring Boot repo layout with one controller."""
    src = tmp_path / "src" / "main" / "java" / "com" / "example"
    src.mkdir(parents=True)
    (src / "UserController.java").write_text(
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class UserController {\n"
        "    @GetMapping(\"/api/users/{id}\")\n"
        "    public ResponseEntity getUser(@PathVariable Long id) { return null; }\n"
        "\n"
        "    @PostMapping(\"/api/users\")\n"
        "    public ResponseEntity createUser(@RequestBody UserRequest req,\n"
        "                                     @RequestParam(required=false) String format) { return null; }\n"
        "}\n"
    )
    return tmp_path


@pytest.fixture
def disc(repo: Path) -> SurfaceDiscovery:
    return SurfaceDiscovery("http://localhost:8080", repo)


# ── Actuator response shapes ──────────────────────────────────────────────────

ACTUATOR_RESPONSE = {
    "contexts": {
        "application": {
            "mappings": {
                "dispatcherServlets": {
                    "dispatcherServlet": [
                        {
                            "handler": "public org.springframework.http.ResponseEntity "
                                       "com.example.UserController.getUser(java.lang.Long)",
                            "predicate": "{GET [/api/users/{id}], produces [application/json]}",
                            "details": {
                                "handlerMethod": {
                                    "className": "com.example.UserController",
                                    "name": "getUser",
                                    "descriptor": "(Ljava/lang/Long;)Lorg/springframework/http/ResponseEntity;",
                                },
                                "requestMappingConditions": {
                                    "methods": ["GET"],
                                    "patterns": ["/api/users/{id}"],
                                    "produces": [{"mediaType": "application/json", "negated": False}],
                                    "consumes": [],
                                },
                            },
                        },
                        {
                            "handler": "public org.springframework.http.ResponseEntity "
                                       "com.example.UserController.createUser(com.example.dto.UserRequest)",
                            "predicate": "{POST [/api/users], consumes [application/json]}",
                            "details": {
                                "handlerMethod": {
                                    "className": "com.example.UserController",
                                    "name": "createUser",
                                    "descriptor": "(Lcom/example/dto/UserRequest;)Lorg/springframework/http/ResponseEntity;",
                                },
                                "requestMappingConditions": {
                                    "methods": ["POST"],
                                    "patterns": ["/api/users"],
                                    "produces": [],
                                    "consumes": [{"mediaType": "application/json", "negated": False}],
                                },
                            },
                        },
                        # Infrastructure endpoint — must be filtered out
                        {
                            "handler": "Actuator web endpoint 'health'",
                            "predicate": "{GET [/actuator/health]}",
                            "details": None,
                        },
                        # Entry with no details — must fall back to predicate parsing
                        {
                            "handler": "ResourceHttpRequestHandler",
                            "predicate": "{GET [/static/index.html]}",
                            "details": {},
                        },
                    ]
                }
            }
        }
    }
}

OPENAPI3_RESPONSE = {
    "openapi": "3.0.1",
    "paths": {
        "/api/orders/{id}": {
            "get": {
                "operationId": "OrderController_getOrder",
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}},
                    {"name": "expand", "in": "query", "required": False, "schema": {"type": "string"}},
                ],
                "responses": {
                    "200": {"content": {"application/json": {}}}
                },
            }
        },
        "/api/orders": {
            "post": {
                "operationId": "OrderController_createOrder",
                "requestBody": {
                    "content": {"application/json": {}}
                },
                "responses": {"201": {}},
            }
        },
        # Infrastructure — must be filtered
        "/actuator/info": {
            "get": {"operationId": "info", "responses": {}}
        },
    }
}

OPENAPI2_RESPONSE = {
    "swagger": "2.0",
    "consumes": ["application/json"],
    "produces": ["application/json"],
    "paths": {
        "/api/products": {
            "get": {
                "operationId": "listProducts",
                "parameters": [
                    {"name": "page", "in": "query", "required": False, "schema": {"type": "integer"}},
                ],
                "responses": {"200": {}},
            }
        }
    }
}


# ── Helper ────────────────────────────────────────────────────────────────────

def _mock_http(status: int, body: dict):
    """Return a mock httpx.Client class that acts as a context manager."""
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = body

    client = MagicMock()
    client.get.return_value = resp
    client.__enter__.return_value = client   # `with httpx.Client() as c` → c is client

    return MagicMock(return_value=client)


def _mock_http_sequence(*responses):
    """
    Yield responses in order across multiple httpx.Client() instantiations.
    Each element is (status, body) or an Exception.
    """
    calls = iter(responses)

    def make_client(*args, **kwargs):
        item = next(calls, None)
        client = MagicMock()
        client.__enter__.return_value = client
        if item is None or isinstance(item, Exception):
            client.get.side_effect = item or Exception("no more responses")
        else:
            status, body = item
            resp = MagicMock()
            resp.status_code = status
            resp.json.return_value = body
            client.get.return_value = resp
        return client

    return MagicMock(side_effect=make_client)


# ── Actuator discovery ────────────────────────────────────────────────────────

class TestActuatorDiscovery:
    def test_discovers_endpoints(self, disc):
        with patch("asel.surface.httpx.Client", _mock_http(200, ACTUATOR_RESPONSE)):
            result = disc.discover()

        assert result.discovery_source == "actuator"
        paths = {e.path for e in result.endpoints}
        assert "/api/users/{id}" in paths
        assert "/api/users" in paths

    def test_filters_actuator_infrastructure(self, disc):
        with patch("asel.surface.httpx.Client", _mock_http(200, ACTUATOR_RESPONSE)):
            result = disc.discover()

        paths = {e.path for e in result.endpoints}
        assert "/actuator/health" not in paths

    def test_correct_http_methods(self, disc):
        with patch("asel.surface.httpx.Client", _mock_http(200, ACTUATOR_RESPONSE)):
            result = disc.discover()

        by_path = {e.path: e for e in result.endpoints}
        assert by_path["/api/users/{id}"].method == "GET"
        assert by_path["/api/users"].method == "POST"

    def test_handler_class_and_method_extracted(self, disc):
        with patch("asel.surface.httpx.Client", _mock_http(200, ACTUATOR_RESPONSE)):
            result = disc.discover()

        ep = next(e for e in result.endpoints if e.path == "/api/users/{id}")
        assert ep.handler_class == "com.example.UserController"
        assert ep.handler_method == "getUser"

    def test_produces_extracted(self, disc):
        with patch("asel.surface.httpx.Client", _mock_http(200, ACTUATOR_RESPONSE)):
            result = disc.discover()

        ep = next(e for e in result.endpoints if e.path == "/api/users/{id}")
        assert "application/json" in ep.produces

    def test_entry_without_details_falls_back_to_predicate(self, disc):
        """Entry with empty details dict should parse path from predicate string."""
        with patch("asel.surface.httpx.Client", _mock_http(200, ACTUATOR_RESPONSE)):
            result = disc.discover()

        paths = {e.path for e in result.endpoints}
        assert "/static/index.html" in paths

    def test_returns_none_on_non_200(self, disc):
        with patch("asel.surface.httpx.Client", _mock_http(404, {})):
            result = disc._try_actuator()
        assert result is None

    def test_returns_none_on_connection_error(self, disc):
        import httpx as httpx_module
        client = MagicMock()
        client.get.side_effect = httpx_module.ConnectError("refused")
        client.__enter__ = lambda s: s
        client.__exit__ = MagicMock(return_value=False)
        with patch("asel.surface.httpx.Client", MagicMock(return_value=client)):
            result = disc._try_actuator()
        assert result is None


# ── OpenAPI discovery ─────────────────────────────────────────────────────────

class TestOpenAPIDiscovery:
    def test_discovers_openapi3_endpoints(self, disc):
        # Actuator returns 404, OpenAPI returns 200
        with patch("asel.surface.httpx.Client",
                   _mock_http_sequence((404, {}), (200, OPENAPI3_RESPONSE))):
            result = disc.discover()

        assert result.discovery_source == "openapi"
        paths = {e.path for e in result.endpoints}
        assert "/api/orders/{id}" in paths
        assert "/api/orders" in paths

    def test_filters_infrastructure_paths_openapi(self, disc):
        with patch("asel.surface.httpx.Client",
                   _mock_http_sequence((404, {}), (200, OPENAPI3_RESPONSE))):
            result = disc.discover()

        paths = {e.path for e in result.endpoints}
        assert "/actuator/info" not in paths

    def test_openapi3_path_parameters(self, disc):
        with patch("asel.surface.httpx.Client",
                   _mock_http_sequence((404, {}), (200, OPENAPI3_RESPONSE))):
            result = disc.discover()

        ep = next(e for e in result.endpoints if e.path == "/api/orders/{id}")
        param_names = {p.name for p in ep.parameters}
        assert "id" in param_names
        assert "expand" in param_names

    def test_openapi3_path_param_is_required(self, disc):
        with patch("asel.surface.httpx.Client",
                   _mock_http_sequence((404, {}), (200, OPENAPI3_RESPONSE))):
            result = disc.discover()

        ep = next(e for e in result.endpoints if e.path == "/api/orders/{id}")
        id_param = next(p for p in ep.parameters if p.name == "id")
        assert id_param.required is True
        assert id_param.location == "path"

    def test_openapi3_request_body_added(self, disc):
        with patch("asel.surface.httpx.Client",
                   _mock_http_sequence((404, {}), (200, OPENAPI3_RESPONSE))):
            result = disc.discover()

        ep = next(e for e in result.endpoints if e.path == "/api/orders")
        locations = {p.location for p in ep.parameters}
        assert "body" in locations

    def test_openapi3_produces_extracted(self, disc):
        with patch("asel.surface.httpx.Client",
                   _mock_http_sequence((404, {}), (200, OPENAPI3_RESPONSE))):
            result = disc.discover()

        ep = next(e for e in result.endpoints if e.path == "/api/orders/{id}")
        assert "application/json" in ep.produces

    def test_openapi2_global_consumes_produces(self, disc):
        with patch("asel.surface.httpx.Client",
                   _mock_http_sequence((404, {}), (404, {}), (200, OPENAPI2_RESPONSE))):
            result = disc.discover()

        assert result.discovery_source == "openapi"
        ep = next(e for e in result.endpoints if e.path == "/api/products")
        assert "application/json" in ep.produces or "application/json" in ep.consumes

    def test_operation_id_class_method_split(self, disc):
        with patch("asel.surface.httpx.Client",
                   _mock_http_sequence((404, {}), (200, OPENAPI3_RESPONSE))):
            result = disc.discover()

        ep = next(e for e in result.endpoints if e.path == "/api/orders/{id}")
        assert ep.handler_class == "OrderController"
        assert ep.handler_method == "getOrder"

    def test_operation_id_no_underscore(self, disc):
        """operationId without underscore → no class, method = operationId."""
        spec = {"paths": {"/foo": {"get": {"operationId": "getFoo", "responses": {}}}}}
        with patch("asel.surface.httpx.Client",
                   _mock_http_sequence((404, {}), (200, spec))):
            result = disc.discover()

        ep = next((e for e in result.endpoints if e.path == "/foo"), None)
        assert ep is not None
        assert ep.handler_class is None
        assert ep.handler_method == "getFoo"


# ── None result when both strategies fail ─────────────────────────────────────

class TestDiscoveryFallback:
    def test_returns_none_source_when_both_fail(self, disc):
        import httpx as httpx_module
        client = MagicMock()
        client.get.side_effect = httpx_module.ConnectError("refused")
        client.__enter__ = lambda s: s
        client.__exit__ = MagicMock(return_value=False)
        with patch("asel.surface.httpx.Client", MagicMock(return_value=client)):
            result = disc.discover()

        assert result.discovery_source == "none"
        assert result.endpoints == []

    def test_returns_none_source_on_all_404(self, disc):
        with patch("asel.surface.httpx.Client",
                   _mock_http_sequence(*[(404, {})] * 6)):
            result = disc.discover()

        assert result.discovery_source == "none"


# ── Source file resolution ────────────────────────────────────────────────────

class TestSourceResolution:
    def test_resolves_java_source_file(self, disc, repo):
        path = disc._resolve_source_file("com.example.UserController")
        assert path == "src/main/java/com/example/UserController.java"

    def test_returns_none_for_unknown_class(self, disc):
        path = disc._resolve_source_file("com.example.NonExistent")
        assert path is None

    def test_strips_inner_class_suffix(self, disc, repo):
        # com.example.UserController$Inner should resolve to UserController.java
        path = disc._resolve_source_file("com.example.UserController$Inner")
        assert path == "src/main/java/com/example/UserController.java"

    def test_resolves_kotlin_source(self, disc, repo):
        kt_dir = repo / "src" / "main" / "kotlin" / "com" / "example"
        kt_dir.mkdir(parents=True)
        (kt_dir / "OrderController.kt").write_text("class OrderController")
        path = disc._resolve_source_file("com.example.OrderController")
        # Should find .kt since .java doesn't exist for this class
        assert path == "src/main/kotlin/com/example/OrderController.kt"


# ── Line resolution ───────────────────────────────────────────────────────────

class TestLineResolution:
    def test_finds_method_line(self, disc):
        line = disc._resolve_source_line(
            "src/main/java/com/example/UserController.java", "getUser"
        )
        assert line == 6  # line 6 in the fixture controller

    def test_finds_second_method(self, disc):
        line = disc._resolve_source_line(
            "src/main/java/com/example/UserController.java", "createUser"
        )
        assert line == 9

    def test_returns_none_for_missing_method(self, disc):
        line = disc._resolve_source_line(
            "src/main/java/com/example/UserController.java", "deleteUser"
        )
        assert line is None

    def test_returns_none_for_missing_file(self, disc):
        line = disc._resolve_source_line("src/main/java/Nonexistent.java", "foo")
        assert line is None


# ── Parameter extraction from source ─────────────────────────────────────────

class TestParameterExtraction:
    def test_extracts_path_variable(self, disc):
        params = disc._extract_params_from_source(
            "src/main/java/com/example/UserController.java", "getUser", 6
        )
        names = {p.name for p in params}
        assert "id" in names

    def test_path_variable_is_required(self, disc):
        params = disc._extract_params_from_source(
            "src/main/java/com/example/UserController.java", "getUser", 6
        )
        id_param = next(p for p in params if p.name == "id")
        assert id_param.location == "path"
        assert id_param.required is True

    def test_extracts_request_body(self, disc):
        params = disc._extract_params_from_source(
            "src/main/java/com/example/UserController.java", "createUser", 9
        )
        locations = {p.location for p in params}
        assert "body" in locations

    def test_extracts_request_param(self, disc):
        params = disc._extract_params_from_source(
            "src/main/java/com/example/UserController.java", "createUser", 9
        )
        names = {p.name for p in params}
        assert "format" in names

    def test_request_param_required_false(self, disc):
        params = disc._extract_params_from_source(
            "src/main/java/com/example/UserController.java", "createUser", 9
        )
        format_param = next((p for p in params if p.name == "format"), None)
        assert format_param is not None
        assert format_param.required is False

    def test_returns_empty_for_missing_file(self, disc):
        params = disc._extract_params_from_source("nonexistent.java", "method", 1)
        assert params == []


# ── End-to-end: actuator + source enrichment ─────────────────────────────────

class TestEndToEndEnrichment:
    def test_source_file_resolved_via_actuator(self, disc):
        with patch("asel.surface.httpx.Client", _mock_http(200, ACTUATOR_RESPONSE)):
            result = disc.discover()

        ep = next(e for e in result.endpoints if e.path == "/api/users/{id}")
        assert ep.source_file == "src/main/java/com/example/UserController.java"

    def test_source_line_resolved_via_actuator(self, disc):
        with patch("asel.surface.httpx.Client", _mock_http(200, ACTUATOR_RESPONSE)):
            result = disc.discover()

        ep = next(e for e in result.endpoints if e.path == "/api/users/{id}")
        assert ep.source_line == 6

    def test_parameters_extracted_via_actuator(self, disc):
        with patch("asel.surface.httpx.Client", _mock_http(200, ACTUATOR_RESPONSE)):
            result = disc.discover()

        ep = next(e for e in result.endpoints if e.path == "/api/users/{id}")
        assert any(p.name == "id" and p.location == "path" for p in ep.parameters)

    def test_mapped_to_source_count(self, disc):
        with patch("asel.surface.httpx.Client", _mock_http(200, ACTUATOR_RESPONSE)):
            result = disc.discover()

        # /api/users/{id} and /api/users both map to UserController
        assert result.mapped_to_source >= 2

    def test_discovery_source_label(self, disc):
        with patch("asel.surface.httpx.Client", _mock_http(200, ACTUATOR_RESPONSE)):
            result = disc.discover()

        for ep in result.endpoints:
            assert ep.discovery_source == "actuator"


# ── web.xml discovery ─────────────────────────────────────────────────────────

WEB_XML_BASIC = """\
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://java.sun.com/xml/ns/javaee" version="2.5">
  <servlet>
    <servlet-name>/login</servlet-name>
    <servlet-class>servlets.Login</servlet-class>
  </servlet>
  <servlet-mapping>
    <servlet-name>/login</servlet-name>
    <url-pattern>/login</url-pattern>
  </servlet-mapping>

  <servlet>
    <servlet-name>/api</servlet-name>
    <servlet-class>servlets.ApiServlet</servlet-class>
  </servlet>
  <servlet-mapping>
    <servlet-name>/api</servlet-name>
    <url-pattern>/api/*</url-pattern>
  </servlet-mapping>

  <!-- catch-all — should be skipped -->
  <servlet>
    <servlet-name>default</servlet-name>
    <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
  </servlet>
  <servlet-mapping>
    <servlet-name>default</servlet-name>
    <url-pattern>/</url-pattern>
  </servlet-mapping>
</web-app>
"""


@pytest.fixture
def servlet_repo(tmp_path: Path) -> Path:
    """Repo with a web.xml and matching servlet source files."""
    webinf = tmp_path / "src" / "main" / "webapp" / "WEB-INF"
    webinf.mkdir(parents=True)
    (webinf / "web.xml").write_text(WEB_XML_BASIC)

    src = tmp_path / "src" / "main" / "java" / "servlets"
    src.mkdir(parents=True)
    (src / "Login.java").write_text(
        "package servlets;\n"
        "public class Login extends javax.servlet.http.HttpServlet {\n"
        "    protected void doPost(HttpServletRequest req, HttpServletResponse resp) {}\n"
        "}\n"
    )
    return tmp_path


@pytest.fixture
def servlet_disc(servlet_repo: Path) -> SurfaceDiscovery:
    return SurfaceDiscovery("http://localhost:8080", servlet_repo)


class TestWebXmlDiscovery:
    def test_discovers_servlet_mappings(self, servlet_disc):
        import httpx as httpx_module
        client = MagicMock()
        client.get.side_effect = httpx_module.ConnectError("refused")
        client.__enter__ = lambda s: s
        client.__exit__ = MagicMock(return_value=False)
        with patch("asel.surface.httpx.Client", MagicMock(return_value=client)):
            result = servlet_disc.discover()

        assert result.discovery_source == "web_xml"
        paths = {e.path for e in result.endpoints}
        assert "/login" in paths
        assert "/api/*" in paths

    def test_skips_root_catch_all(self, servlet_disc):
        import httpx as httpx_module
        client = MagicMock()
        client.get.side_effect = httpx_module.ConnectError("refused")
        client.__enter__ = lambda s: s
        client.__exit__ = MagicMock(return_value=False)
        with patch("asel.surface.httpx.Client", MagicMock(return_value=client)):
            result = servlet_disc.discover()

        paths = {e.path for e in result.endpoints}
        assert "/" not in paths

    def test_handler_class_set(self, servlet_disc):
        import httpx as httpx_module
        client = MagicMock()
        client.get.side_effect = httpx_module.ConnectError("refused")
        client.__enter__ = lambda s: s
        client.__exit__ = MagicMock(return_value=False)
        with patch("asel.surface.httpx.Client", MagicMock(return_value=client)):
            result = servlet_disc.discover()

        ep = next(e for e in result.endpoints if e.path == "/login")
        assert ep.handler_class == "servlets.Login"

    def test_source_file_resolved(self, servlet_disc, servlet_repo):
        import httpx as httpx_module
        client = MagicMock()
        client.get.side_effect = httpx_module.ConnectError("refused")
        client.__enter__ = lambda s: s
        client.__exit__ = MagicMock(return_value=False)
        with patch("asel.surface.httpx.Client", MagicMock(return_value=client)):
            result = servlet_disc.discover()

        ep = next(e for e in result.endpoints if e.path == "/login")
        assert ep.source_file == "src/main/java/servlets/Login.java"

    def test_method_defaults_to_get(self, servlet_disc):
        import httpx as httpx_module
        client = MagicMock()
        client.get.side_effect = httpx_module.ConnectError("refused")
        client.__enter__ = lambda s: s
        client.__exit__ = MagicMock(return_value=False)
        with patch("asel.surface.httpx.Client", MagicMock(return_value=client)):
            result = servlet_disc.discover()

        ep = next(e for e in result.endpoints if e.path == "/login")
        assert ep.method == "GET"

    def test_actuator_takes_precedence_over_web_xml(self, servlet_disc):
        """Actuator discovery wins if the app responds on /actuator/mappings."""
        with patch("asel.surface.httpx.Client", _mock_http(200, ACTUATOR_RESPONSE)):
            result = servlet_disc.discover()

        assert result.discovery_source == "actuator"

    def test_no_web_xml_returns_none(self, disc):
        """Repo without web.xml falls through to 'none'."""
        import httpx as httpx_module
        client = MagicMock()
        client.get.side_effect = httpx_module.ConnectError("refused")
        client.__enter__ = lambda s: s
        client.__exit__ = MagicMock(return_value=False)
        with patch("asel.surface.httpx.Client", MagicMock(return_value=client)):
            result = disc.discover()

        assert result.discovery_source == "none"

    def test_mapped_to_source_count(self, servlet_disc):
        import httpx as httpx_module
        client = MagicMock()
        client.get.side_effect = httpx_module.ConnectError("refused")
        client.__enter__ = lambda s: s
        client.__exit__ = MagicMock(return_value=False)
        with patch("asel.surface.httpx.Client", MagicMock(return_value=client)):
            result = servlet_disc.discover()

        # /login maps to Login.java; /api/* has no source → mapped_to_source == 1
        assert result.mapped_to_source == 1

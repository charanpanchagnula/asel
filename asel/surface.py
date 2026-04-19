# asel/surface.py
"""
Phase 2b — Surface Discovery

Given a running JVM web service, discovers its HTTP surface by querying:
  1. /actuator/mappings  — Spring's internal route registry (most complete)
  2. /v3/api-docs        — OpenAPI 3.0 spec (Springdoc / Swagger)
  3. /v2/api-docs        — OpenAPI 2.0 / Swagger spec (legacy)

For each discovered endpoint, attempts to resolve the handler back to a
source file and line number in the repo so the exploit engine can link
SAST findings directly to reachable HTTP routes.

Usage:
    disc = SurfaceDiscovery(base_url="http://localhost:8080", repo_path=repo)
    result = disc.discover()
    # result.endpoints — list[HttpEndpoint] with source_file/line where found
"""
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

import httpx

from .models import EndpointParameter, HttpEndpoint, SurfaceDiscoveryResult

logger = logging.getLogger(__name__)

# Paths tried for each discovery strategy, in order
_ACTUATOR_PATHS = ["/actuator/mappings"]
_OPENAPI_PATHS  = ["/v3/api-docs", "/v2/api-docs", "/api-docs"]

# Spring annotation patterns used to extract parameters from source
_PARAM_PATTERNS: list[tuple[str, str, bool]] = [
    # (annotation_pattern, location, required)
    (r"@PathVariable(?:\([^)]*\))?\s+[\w<>,\s]+\s+(\w+)", "path",   True),
    (r"@RequestParam(?:\([^)]*\))?\s+[\w<>,\s]+\s+(\w+)", "query",  False),
    (r"@RequestBody(?:\([^)]*\))?\s+[\w<>,\s]+\s+(\w+)",  "body",   True),
    (r"@RequestHeader(?:\([^)]*\))?\s+[\w<>,\s]+\s+(\w+)","header", False),
]

# Endpoints that are Spring infrastructure — skip them, not useful for probing
_SKIP_PATH_PREFIXES = ("/actuator", "/error", "/webjars", "/swagger-ui", "/v3/api-docs")


class SurfaceDiscovery:
    """
    Discovers the HTTP surface of a running JVM web service and resolves
    each route back to its source file + line in the repository.
    """

    def __init__(self, base_url: str, repo_path: Path):
        self._base_url = base_url.rstrip("/")
        self._repo_path = repo_path.resolve()

    def discover(self) -> SurfaceDiscoveryResult:
        """
        Try actuator/mappings first, then OpenAPI, then static web.xml analysis.
        Returns whatever we find. Never raises — returns an empty result if all fail.
        """
        result = self._try_actuator()
        if result is not None:
            return result

        result = self._try_openapi()
        if result is not None:
            return result

        result = self._try_web_xml()
        if result is not None:
            return result

        result = self._try_source_scan()
        if result is not None:
            return result

        logger.info("Surface discovery: no actuator, OpenAPI, web.xml, or annotation mappings found")
        return SurfaceDiscoveryResult(discovery_source="none")

    # ── Actuator strategy ─────────────────────────────────────────────────────

    def _try_actuator(self) -> Optional[SurfaceDiscoveryResult]:
        for path in _ACTUATOR_PATHS:
            try:
                with httpx.Client(timeout=10.0) as client:
                    resp = client.get(f"{self._base_url}{path}")
                if resp.status_code != 200:
                    continue
                data = resp.json()
                endpoints = self._parse_actuator(data)
                if not endpoints:
                    continue
                endpoints = self._enrich(endpoints)
                logger.info(
                    "Actuator: found %d endpoints (%d mapped to source)",
                    len(endpoints),
                    sum(1 for e in endpoints if e.source_file),
                )
                return SurfaceDiscoveryResult(
                    endpoints=endpoints,
                    discovery_source="actuator",
                    mapped_to_source=sum(1 for e in endpoints if e.source_file),
                )
            except Exception as exc:
                logger.debug("Actuator discovery failed (%s): %s", path, exc)
        return None

    def _parse_actuator(self, data: dict) -> list[HttpEndpoint]:
        """
        Parse Spring Boot's /actuator/mappings JSON into HttpEndpoint objects.
        Handles both 2.x and 3.x response shapes.
        """
        endpoints: list[HttpEndpoint] = []

        # The tree: contexts → <ctx name> → mappings → dispatcherServlets → <name> → [entries]
        contexts = data.get("contexts", {})
        for ctx in contexts.values():
            mappings = ctx.get("mappings", {})
            for servlet_entries in mappings.get("dispatcherServlets", {}).values():
                for entry in servlet_entries:
                    parsed = self._parse_actuator_entry(entry)
                    if parsed:
                        endpoints.extend(parsed)

        return [e for e in endpoints if not self._is_infrastructure(e.path)]

    def _parse_actuator_entry(self, entry: dict) -> list[HttpEndpoint]:
        """Parse a single dispatcher servlet mapping entry."""
        details = entry.get("details") or {}
        handler_info = details.get("handlerMethod", {})
        conditions = details.get("requestMappingConditions", {})

        handler_class  = handler_info.get("className")
        handler_method = handler_info.get("name")

        # Extract HTTP methods (empty list = all methods — default to GET for now)
        methods = conditions.get("methods") or ["GET"]

        # Extract path patterns
        patterns = conditions.get("patterns") or []
        if not patterns:
            # Fall back to parsing the predicate string: "{GET [/api/users/{id}]}"
            predicate = entry.get("predicate", "")
            patterns = re.findall(r"\[(/[^\]]*)\]", predicate)
            if not patterns:
                return []

        consumes = [c.get("mediaType", "") for c in conditions.get("consumes", [])]
        produces = [p.get("mediaType", "") for p in conditions.get("produces", [])]

        result = []
        for method in methods:
            for path in patterns:
                result.append(HttpEndpoint(
                    method=method.upper(),
                    path=path,
                    handler_class=handler_class,
                    handler_method=handler_method,
                    consumes=consumes,
                    produces=produces,
                    discovery_source="actuator",
                ))
        return result

    # ── OpenAPI strategy ──────────────────────────────────────────────────────

    def _try_openapi(self) -> Optional[SurfaceDiscoveryResult]:
        for path in _OPENAPI_PATHS:
            try:
                with httpx.Client(timeout=10.0) as client:
                    resp = client.get(f"{self._base_url}{path}")
                if resp.status_code != 200:
                    continue
                data = resp.json()
                endpoints = self._parse_openapi(data)
                if not endpoints:
                    continue
                endpoints = self._enrich(endpoints)
                logger.info(
                    "OpenAPI: found %d endpoints (%d mapped to source)",
                    len(endpoints),
                    sum(1 for e in endpoints if e.source_file),
                )
                return SurfaceDiscoveryResult(
                    endpoints=endpoints,
                    discovery_source="openapi",
                    mapped_to_source=sum(1 for e in endpoints if e.source_file),
                )
            except Exception as exc:
                logger.debug("OpenAPI discovery failed (%s): %s", path, exc)
        return None

    def _parse_openapi(self, spec: dict) -> list[HttpEndpoint]:
        """Parse an OpenAPI 2.x or 3.x spec into HttpEndpoint objects."""
        endpoints: list[HttpEndpoint] = []
        paths = spec.get("paths", {})

        for path, path_item in paths.items():
            if self._is_infrastructure(path):
                continue
            for method, operation in path_item.items():
                if method.upper() not in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
                    continue
                if not isinstance(operation, dict):
                    continue

                params = self._parse_openapi_params(operation.get("parameters", []))
                # Request body (OpenAPI 3.x)
                if "requestBody" in operation:
                    params.append(EndpointParameter(
                        name="body", location="body", required=True
                    ))

                # Infer handler from operationId if available (e.g. "UserController_getUser")
                operation_id = operation.get("operationId", "")
                handler_class, handler_method = self._parse_operation_id(operation_id)

                consumes = self._openapi_consumes(spec, operation)
                produces = self._openapi_produces(spec, operation)

                endpoints.append(HttpEndpoint(
                    method=method.upper(),
                    path=path,
                    handler_class=handler_class,
                    handler_method=handler_method,
                    parameters=params,
                    consumes=consumes,
                    produces=produces,
                    discovery_source="openapi",
                ))
        return endpoints

    def _parse_openapi_params(self, params_spec: list) -> list[EndpointParameter]:
        result = []
        for p in params_spec:
            if not isinstance(p, dict):
                continue
            schema = p.get("schema", {})
            result.append(EndpointParameter(
                name=p.get("name", ""),
                location=p.get("in", "query"),
                required=p.get("required", False),
                param_type=schema.get("type", "string"),
            ))
        return result

    def _parse_operation_id(self, operation_id: str) -> tuple[Optional[str], Optional[str]]:
        """
        Try to extract class and method from an operationId.
        Springdoc generates operationIds like "getUser" or "UserController_getUser".
        """
        if not operation_id:
            return None, None
        if "_" in operation_id:
            parts = operation_id.split("_", 1)
            return parts[0], parts[1]
        return None, operation_id

    def _openapi_consumes(self, spec: dict, operation: dict) -> list[str]:
        """Extract request content types from OpenAPI 2.x or 3.x."""
        # OpenAPI 3.x
        rb = operation.get("requestBody", {})
        if rb:
            return list(rb.get("content", {}).keys())
        # OpenAPI 2.x
        return operation.get("consumes", spec.get("consumes", []))

    def _openapi_produces(self, spec: dict, operation: dict) -> list[str]:
        """Extract response content types from OpenAPI 2.x or 3.x."""
        responses = operation.get("responses", {})
        for resp in responses.values():
            if isinstance(resp, dict) and "content" in resp:
                return list(resp["content"].keys())
        return operation.get("produces", spec.get("produces", []))

    # ── Source resolution ─────────────────────────────────────────────────────

    # ── web.xml strategy ─────────────────────────────────────────────────────

    def _try_web_xml(self) -> Optional[SurfaceDiscoveryResult]:
        """
        Parse WEB-INF/web.xml to discover servlet-mapped URL patterns.

        This is a static analysis fallback for classic Servlet / Spring MVC WARs that
        have no Spring Boot actuator and no Swagger/OpenAPI spec.  The web.xml declares
        servlet classes and their URL mappings but not HTTP methods, so every discovered
        endpoint is given method ``GET`` (most servlet endpoints accept GET; callers that
        need POST coverage should probe both).

        Searches in order:
          1. src/main/webapp/WEB-INF/web.xml  (source tree — always present)
          2. target/*/WEB-INF/web.xml          (exploded WAR — present after build)
        """
        web_xml = self._find_web_xml()
        if web_xml is None:
            return None
        try:
            endpoints = self._parse_web_xml(web_xml)
        except Exception as exc:
            logger.debug("web.xml parse error (%s): %s", web_xml, exc)
            return None
        if not endpoints:
            return None
        endpoints = self._enrich(endpoints)
        logger.info(
            "web.xml: found %d endpoints (%d mapped to source)",
            len(endpoints),
            sum(1 for e in endpoints if e.source_file),
        )
        return SurfaceDiscoveryResult(
            endpoints=endpoints,
            discovery_source="web_xml",
            mapped_to_source=sum(1 for e in endpoints if e.source_file),
        )

    def _find_web_xml(self) -> Optional[Path]:
        """Return the first web.xml found in the expected locations."""
        candidates = [
            self._repo_path / "src" / "main" / "webapp" / "WEB-INF" / "web.xml",
            self._repo_path / "src" / "main" / "webApp" / "WEB-INF" / "web.xml",
            self._repo_path / "WebContent" / "WEB-INF" / "web.xml",
        ]
        for c in candidates:
            if c.exists():
                return c
        # Exploded WAR: target/<app-name>/WEB-INF/web.xml
        target = self._repo_path / "target"
        if target.is_dir():
            for child in sorted(target.iterdir()):
                candidate = child / "WEB-INF" / "web.xml"
                if candidate.exists():
                    return candidate
        return None

    def _parse_web_xml(self, web_xml: Path) -> list[HttpEndpoint]:
        """
        Parse a web.xml file into HttpEndpoint objects.

        Builds two maps:
          servlet_name → servlet_class  (from <servlet> elements)
          servlet_name → [url_patterns] (from <servlet-mapping> elements)

        Then joins them to produce one HttpEndpoint per URL pattern with
        ``method=GET`` and the servlet class as the handler.
        """
        tree = ET.parse(web_xml)
        root = tree.getroot()

        # Strip XML namespace from tag names so we can use simple tag comparisons.
        # web.xml namespaces look like {http://java.sun.com/xml/ns/javaee}servlet.
        def _tag(elem: ET.Element) -> str:
            return elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag

        def _text(elem: Optional[ET.Element]) -> str:
            return (elem.text or "").strip() if elem is not None else ""

        # Build servlet-name → class map
        servlet_classes: dict[str, str] = {}
        for servlet in root.iter():
            if _tag(servlet) != "servlet":
                continue
            name = _text(servlet.find(
                f"{{{servlet.tag.split('}')[0][1:]}}}servlet-name"
                if "}" in servlet.tag else "servlet-name"
            ))
            cls = _text(servlet.find(
                f"{{{servlet.tag.split('}')[0][1:]}}}servlet-class"
                if "}" in servlet.tag else "servlet-class"
            ))
            if not name and not cls:
                # Fallback: iterate children directly
                for child in servlet:
                    t = _tag(child)
                    if t == "servlet-name":
                        name = _text(child)
                    elif t == "servlet-class":
                        cls = _text(child)
            if name and cls:
                servlet_classes[name] = cls

        # Build servlet-name → url-patterns map
        servlet_patterns: dict[str, list[str]] = {}
        for mapping in root.iter():
            if _tag(mapping) != "servlet-mapping":
                continue
            name = ""
            patterns: list[str] = []
            for child in mapping:
                t = _tag(child)
                if t == "servlet-name":
                    name = _text(child)
                elif t == "url-pattern":
                    p = _text(child)
                    if p:
                        patterns.append(p)
            if name and patterns:
                servlet_patterns.setdefault(name, []).extend(patterns)

        # Join and produce endpoints.  Skip wildcard-only entries like "/*" which
        # are usually security filters, not real business endpoints.
        endpoints: list[HttpEndpoint] = []
        for name, cls in servlet_classes.items():
            patterns = servlet_patterns.get(name, [])
            for pattern in patterns:
                if pattern in ("/", "/*", "*.jsp", "*.html"):
                    continue  # skip catch-all mappings
                endpoints.append(HttpEndpoint(
                    method="GET",
                    path=pattern,
                    handler_class=cls,
                    discovery_source="web_xml",
                ))
        return endpoints

    def _enrich(self, endpoints: list[HttpEndpoint]) -> list[HttpEndpoint]:
        """Resolve source file + line and extract parameters for each endpoint."""
        for ep in endpoints:
            if ep.handler_class:
                ep.source_file = self._resolve_source_file(ep.handler_class)
            if ep.source_file and ep.handler_method:
                ep.source_line = self._resolve_source_line(ep.source_file, ep.handler_method)
            if ep.source_file and ep.handler_method and not ep.parameters:
                ep.parameters = self._extract_params_from_source(
                    ep.source_file, ep.handler_method, ep.source_line or 1
                )
        return endpoints

    def _resolve_source_file(self, class_name: str) -> Optional[str]:
        """
        Map a fully-qualified class name to its source file path in the repo.
        e.g. "com.example.UserController" → "src/main/java/com/example/UserController.java"
        """
        # Strip inner class suffix (com.example.Outer$Inner → com.example.Outer)
        class_name = class_name.split("$")[0]
        rel_path = class_name.replace(".", "/")

        for src_root in (
            "src/main/java",
            "src/main/kotlin",
            "src/main/groovy",
            "src",
        ):
            for ext in (".java", ".kt", ".groovy"):
                candidate = self._repo_path / src_root / (rel_path + ext)
                if candidate.exists():
                    return str(candidate.relative_to(self._repo_path))
        return None

    def _resolve_source_line(self, source_file: str, method_name: str) -> Optional[int]:
        """
        Find the line number of a method definition in a source file.
        Returns the first line that looks like a method signature.
        """
        f = self._repo_path / source_file
        if not f.exists():
            return None
        try:
            lines = f.read_text(errors="replace").splitlines()
        except OSError:
            return None

        # Look for method definition: return_type methodName(
        pattern = re.compile(rf"\b{re.escape(method_name)}\s*\(")
        for i, line in enumerate(lines, 1):
            if pattern.search(line):
                return i
        return None

    def _extract_params_from_source(
        self, source_file: str, method_name: str, start_line: int
    ) -> list[EndpointParameter]:
        """
        Extract @PathVariable, @RequestParam, @RequestBody, @RequestHeader
        annotations from the method signature in the source file.
        """
        f = self._repo_path / source_file
        if not f.exists():
            return []
        try:
            lines = f.read_text(errors="replace").splitlines()
        except OSError:
            return []

        # Read from the method start through the opening brace — covers multi-line signatures
        start = max(0, start_line - 1)
        snippet_lines = []
        for line in lines[start:start + 20]:
            snippet_lines.append(line)
            if "{" in line:
                break
        snippet = "\n".join(snippet_lines)

        params: list[EndpointParameter] = []
        for annotation_pattern, location, required in _PARAM_PATTERNS:
            for m in re.finditer(annotation_pattern, snippet):
                param_name = m.group(1)
                # @RequestParam(required=false) overrides the default
                if location == "query":
                    window = snippet[max(0, m.start() - 50): m.end()]
                    required = not bool(re.search(r"required\s*=\s*false", window, re.IGNORECASE))
                params.append(EndpointParameter(
                    name=param_name,
                    location=location,
                    required=required,
                ))
        return params

    # ── Static source scan strategy ───────────────────────────────────────────

    # Spring mapping annotations and the HTTP method they imply
    _MAPPING_ANNOTATIONS: list[tuple[str, str]] = [
        ("@GetMapping",     "GET"),
        ("@PostMapping",    "POST"),
        ("@PutMapping",     "PUT"),
        ("@DeleteMapping",  "DELETE"),
        ("@PatchMapping",   "PATCH"),
        ("@RequestMapping", "GET"),   # default method; overridden by method= attr
    ]

    # Regex to extract path value from annotation, e.g. @GetMapping("/api/users/{id}")
    _PATH_RE = re.compile(r'@\w+Mapping\s*\(\s*(?:value\s*=\s*)?["\{]([^"}\)]+)')
    _METHOD_RE = re.compile(r'method\s*=\s*RequestMethod\.(\w+)')

    def _try_source_scan(self) -> Optional[SurfaceDiscoveryResult]:
        """
        Static fallback: scan Java/Kotlin source files for Spring mapping annotations.
        Used when the running app doesn't expose actuator or OpenAPI endpoints.
        Only meaningful when the app is actually running (caller's responsibility).
        """
        endpoints: list[HttpEndpoint] = []
        src_roots = [
            self._repo_path / "src" / "main" / "java",
            self._repo_path / "src" / "main" / "kotlin",
        ]
        source_files = []
        for root in src_roots:
            if root.exists():
                source_files.extend(root.rglob("*.java"))
                source_files.extend(root.rglob("*.kt"))

        if not source_files:
            return None

        for src_file in source_files:
            try:
                endpoints.extend(self._scan_source_file(src_file))
            except Exception as exc:
                logger.debug("Source scan error in %s: %s", src_file, exc)

        endpoints = [e for e in endpoints if not self._is_infrastructure(e.path)]
        if not endpoints:
            return None

        logger.info(
            "Source scan: found %d endpoint(s) from annotation scanning",
            len(endpoints),
        )
        return SurfaceDiscoveryResult(
            endpoints=endpoints,
            discovery_source="source_scan",
            mapped_to_source=sum(1 for e in endpoints if e.source_file),
        )

    def _scan_source_file(self, src_file: Path) -> list[HttpEndpoint]:
        """Extract Spring-annotated HTTP endpoints from a single source file."""
        try:
            text = src_file.read_text(errors="replace")
        except OSError:
            return []

        rel_path = str(src_file.relative_to(self._repo_path))
        endpoints: list[HttpEndpoint] = []

        # Extract class-level base path if present
        class_path = ""
        class_mapping = re.search(
            r'@RequestMapping\s*\(\s*(?:value\s*=\s*)?["\{]([^"}\)]+)', text
        )
        if class_mapping:
            class_path = "/" + class_mapping.group(1).strip("/")

        # Find handler class name from file stem
        handler_class = src_file.stem

        lines = text.splitlines()
        for i, line in enumerate(lines):
            for annotation, default_method in self._MAPPING_ANNOTATIONS:
                if annotation not in line:
                    continue

                # Extract path
                path_m = self._PATH_RE.search(line)
                if not path_m:
                    # Multi-line annotation — join next line
                    joined = line + (lines[i + 1] if i + 1 < len(lines) else "")
                    path_m = self._PATH_RE.search(joined)
                if not path_m:
                    continue

                method_path = "/" + path_m.group(1).strip("/")
                full_path = (class_path + method_path).replace("//", "/")
                if self._is_infrastructure(full_path):
                    continue

                # Override HTTP method if method= attribute present
                http_method = default_method
                method_m = self._METHOD_RE.search(line)
                if method_m:
                    http_method = method_m.group(1).upper()

                # Extract handler method name from next non-blank line
                handler_method = None
                for offset in range(1, 5):
                    if i + offset >= len(lines):
                        break
                    next_line = lines[i + offset].strip()
                    if next_line and not next_line.startswith("@"):
                        m = re.search(r'\b(\w+)\s*\(', next_line)
                        if m:
                            handler_method = m.group(1)
                        break

                # Extract parameters from the method signature
                params: list[EndpointParameter] = []
                if handler_method:
                    params = self._extract_params_from_source(rel_path, handler_method, i + 1)

                endpoints.append(HttpEndpoint(
                    method=http_method,
                    path=full_path,
                    handler_class=handler_class,
                    handler_method=handler_method,
                    source_file=rel_path,
                    source_line=i + 1,
                    parameters=params,
                    discovery_source="source_scan",
                ))

        return endpoints

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _is_infrastructure(self, path: str) -> bool:
        """Skip Spring infrastructure and framework endpoints."""
        return any(path.startswith(prefix) for prefix in _SKIP_PATH_PREFIXES)

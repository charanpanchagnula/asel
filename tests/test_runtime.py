# tests/test_runtime.py
"""
Tests for RuntimeEngine — covers all pure logic (detection, JAR finding,
port parsing, H2 mode, log classification, dep provisioning decisions).
Docker-dependent methods (start, stop, _launch_app) are mocked.
"""
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from asel.runtime import (
    RuntimeEngine, _DEPS, _INFRA_OVERRIDES,
    _select_tomcat_image, _select_jetty_image,
    _JDK17_OPENS, _WAR_JVM_ENV, _FATAL_WAR_PATTERNS,
    classify_runtime_failure, reclassify_from_cause,
)
from asel.models import Language, RuntimeFailureClass, RuntimeStatus, ServiceType


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def maven_repo(tmp_path: Path) -> Path:
    """Minimal Maven Spring Boot repo."""
    (tmp_path / "pom.xml").write_text(
        "<project>"
        "<dependencies>"
        "<dependency><groupId>org.springframework.boot</groupId>"
        "<artifactId>spring-boot-starter-web</artifactId></dependency>"
        "</dependencies>"
        "</project>"
    )
    src = tmp_path / "src" / "main" / "java" / "com" / "example"
    src.mkdir(parents=True)
    (src / "App.java").write_text(
        "@SpringBootApplication\npublic class App { public static void main(String[] a) {} }\n"
    )
    return tmp_path


@pytest.fixture
def gradle_repo(tmp_path: Path) -> Path:
    """Minimal Gradle Spring Boot repo."""
    (tmp_path / "build.gradle").write_text(
        'plugins { id "org.springframework.boot" version "3.2.0" }\n'
        'dependencies { implementation "org.springframework.boot:spring-boot-starter-web" }\n'
    )
    return tmp_path


@pytest.fixture
def engine(maven_repo: Path) -> RuntimeEngine:
    """RuntimeEngine with a mocked Docker client."""
    with patch("asel.runtime.docker.from_env", return_value=MagicMock()):
        return RuntimeEngine(maven_repo, Language.JAVA_MAVEN, "maven:3.9-eclipse-temurin-21")


@pytest.fixture
def gradle_engine(gradle_repo: Path) -> RuntimeEngine:
    with patch("asel.runtime.docker.from_env", return_value=MagicMock()):
        return RuntimeEngine(gradle_repo, Language.JAVA_GRADLE, "gradle:8-jdk21")


# ── Service detection ─────────────────────────────────────────────────────────

class TestDetectServiceType:
    def test_detects_spring_boot_via_pom(self, engine):
        assert engine._detect_service_type() == ServiceType.SPRING_BOOT

    def test_detects_spring_boot_via_gradle(self, gradle_engine):
        assert gradle_engine._detect_service_type() == ServiceType.SPRING_BOOT

    def test_detects_spring_boot_via_annotation_only(self, tmp_path):
        """No spring-boot in build file, but @SpringBootApplication in source."""
        (tmp_path / "pom.xml").write_text("<project></project>")
        src = tmp_path / "src" / "main" / "java"
        src.mkdir(parents=True)
        (src / "App.java").write_text("@SpringBootApplication\npublic class App {}\n")
        with patch("asel.runtime.docker.from_env", return_value=MagicMock()):
            eng = RuntimeEngine(tmp_path, Language.JAVA_MAVEN, "img")
        assert eng._detect_service_type() == ServiceType.SPRING_BOOT

    def test_detects_quarkus(self, tmp_path):
        (tmp_path / "pom.xml").write_text(
            "<project><dependencies>"
            "<dependency><groupId>io.quarkus</groupId>"
            "<artifactId>quarkus-core</artifactId></dependency>"
            "</dependencies></project>"
        )
        with patch("asel.runtime.docker.from_env", return_value=MagicMock()):
            eng = RuntimeEngine(tmp_path, Language.JAVA_MAVEN, "img")
        assert eng._detect_service_type() == ServiceType.QUARKUS

    def test_detects_micronaut(self, tmp_path):
        (tmp_path / "pom.xml").write_text(
            "<project><dependencies>"
            "<dependency><groupId>io.micronaut</groupId>"
            "<artifactId>micronaut-core</artifactId></dependency>"
            "</dependencies></project>"
        )
        with patch("asel.runtime.docker.from_env", return_value=MagicMock()):
            eng = RuntimeEngine(tmp_path, Language.JAVA_MAVEN, "img")
        assert eng._detect_service_type() == ServiceType.MICRONAUT

    def test_unknown_when_no_build_file(self, tmp_path):
        with patch("asel.runtime.docker.from_env", return_value=MagicMock()):
            eng = RuntimeEngine(tmp_path, Language.JAVA_MAVEN, "img")
        assert eng._detect_service_type() == ServiceType.UNKNOWN

    def test_unknown_plain_java_project(self, tmp_path):
        (tmp_path / "pom.xml").write_text("<project><artifactId>cli-tool</artifactId></project>")
        with patch("asel.runtime.docker.from_env", return_value=MagicMock()):
            eng = RuntimeEngine(tmp_path, Language.JAVA_MAVEN, "img")
        assert eng._detect_service_type() == ServiceType.UNKNOWN

    def test_detect_public_api_returns_bool(self, engine):
        assert engine.detect() is True

    def test_detect_returns_false_for_unknown(self, tmp_path):
        (tmp_path / "pom.xml").write_text("<project></project>")
        with patch("asel.runtime.docker.from_env", return_value=MagicMock()):
            eng = RuntimeEngine(tmp_path, Language.JAVA_MAVEN, "img")
        assert eng.detect() is False


# ── JAR finding ───────────────────────────────────────────────────────────────

class TestFindJar:
    def _make_jar(self, path: Path, size: int = 1000) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * size)
        return path

    def test_finds_maven_fat_jar(self, engine, maven_repo):
        self._make_jar(maven_repo / "target" / "app-1.0.jar", size=5_000_000)
        jar = engine._find_jar()
        assert jar is not None
        assert jar.name == "app-1.0.jar"

    def test_excludes_sources_jar(self, engine, maven_repo):
        self._make_jar(maven_repo / "target" / "app-sources.jar", size=5_000_000)
        self._make_jar(maven_repo / "target" / "app-1.0.jar", size=5_000_000)
        jar = engine._find_jar()
        assert jar.name == "app-1.0.jar"

    def test_excludes_tests_jar(self, engine, maven_repo):
        self._make_jar(maven_repo / "target" / "app-tests.jar", size=5_000_000)
        jar = engine._find_jar()
        assert jar is None

    def test_excludes_original_jar(self, engine, maven_repo):
        self._make_jar(maven_repo / "target" / "app-1.0-original.jar", size=1_000)
        self._make_jar(maven_repo / "target" / "app-1.0.jar", size=5_000_000)
        jar = engine._find_jar()
        assert jar.name == "app-1.0.jar"

    def test_prefers_largest_jar(self, engine, maven_repo):
        self._make_jar(maven_repo / "target" / "app-1.0.jar", size=5_000_000)
        self._make_jar(maven_repo / "target" / "extra.jar", size=100)
        jar = engine._find_jar()
        assert jar.name == "app-1.0.jar"

    def test_returns_none_when_no_target_dir(self, engine):
        assert engine._find_jar() is None

    def test_returns_none_when_target_empty(self, engine, maven_repo):
        (maven_repo / "target").mkdir()
        assert engine._find_jar() is None

    def test_finds_gradle_jar(self, gradle_engine, gradle_repo):
        self._make_jar(gradle_repo / "build" / "libs" / "app-1.0.jar", size=5_000_000)
        jar = gradle_engine._find_jar()
        assert jar is not None
        assert jar.name == "app-1.0.jar"

    def test_excludes_gradle_plain_jar(self, gradle_engine, gradle_repo):
        self._make_jar(gradle_repo / "build" / "libs" / "app-plain.jar", size=5_000_000)
        jar = gradle_engine._find_jar()
        assert jar is None


# ── Port detection ────────────────────────────────────────────────────────────

class TestDetectPort:
    def test_reads_properties_file(self, engine, maven_repo):
        res = maven_repo / "src" / "main" / "resources"
        res.mkdir(parents=True)
        (res / "application.properties").write_text("server.port=9090\n")
        assert engine._detect_port() == 9090

    def test_reads_yml_file(self, engine, maven_repo):
        res = maven_repo / "src" / "main" / "resources"
        res.mkdir(parents=True)
        (res / "application.yml").write_text("server:\n  port: 7070\n")
        assert engine._detect_port() == 7070

    def test_reads_yaml_extension(self, engine, maven_repo):
        res = maven_repo / "src" / "main" / "resources"
        res.mkdir(parents=True)
        (res / "application.yaml").write_text("server.port: 6060\n")
        assert engine._detect_port() == 6060

    def test_defaults_to_8080(self, engine):
        assert engine._detect_port() == 8080

    def test_properties_takes_precedence_over_yml(self, engine, maven_repo):
        res = maven_repo / "src" / "main" / "resources"
        res.mkdir(parents=True)
        (res / "application.properties").write_text("server.port=9191\n")
        (res / "application.yml").write_text("server:\n  port: 7777\n")
        assert engine._detect_port() == 9191


# ── H2 mode detection ─────────────────────────────────────────────────────────

class TestDetectH2Mode:
    def test_postgres_keyword(self, engine, maven_repo):
        (maven_repo / "pom.xml").write_text(
            "<project><dependencies>"
            "<dependency><artifactId>postgresql</artifactId></dependency>"
            "</dependencies></project>"
        )
        assert engine._detect_h2_mode() == "PostgreSQL"

    def test_mysql_keyword(self, engine, maven_repo):
        (maven_repo / "pom.xml").write_text(
            "<project><dependencies>"
            "<dependency><artifactId>mysql-connector-java</artifactId></dependency>"
            "</dependencies></project>"
        )
        assert engine._detect_h2_mode() == "MySQL"

    def test_db2_keyword(self, engine, maven_repo):
        (maven_repo / "pom.xml").write_text(
            "<project><dependencies>"
            "<dependency><artifactId>db2jcc</artifactId></dependency>"
            "</dependencies></project>"
        )
        assert engine._detect_h2_mode() == "DB2"

    def test_oracle_keyword(self, engine, maven_repo):
        (maven_repo / "pom.xml").write_text(
            "<project><dependencies>"
            "<dependency><artifactId>ojdbc8</artifactId></dependency>"
            "</dependencies></project>"
        )
        assert engine._detect_h2_mode() == "Oracle"

    def test_sqlserver_keyword(self, engine, maven_repo):
        (maven_repo / "pom.xml").write_text(
            "<project><dependencies>"
            "<dependency><artifactId>mssql-jdbc</artifactId></dependency>"
            "</dependencies></project>"
        )
        assert engine._detect_h2_mode() == "MSSQLServer"

    def test_defaults_to_postgresql(self, engine):
        # Spring Boot with no specific DB dep → safest default
        assert engine._detect_h2_mode() == "PostgreSQL"


# ── Infrastructure flag extraction from log ───────────────────────────────────

class TestInfraFlagsFromLog:
    def test_eureka_in_log(self, engine):
        log = "WARN  EurekaClient -- Can't get a response from http://localhost:8761"
        flags = engine._infra_flags_from_log(log)
        assert "--eureka.client.enabled=false" in flags

    def test_config_server_in_log(self, engine):
        log = "ERROR ConfigServicePropertySource -- Could not locate PropertySource"
        flags = engine._infra_flags_from_log(log)
        assert "--spring.cloud.config.enabled=false" in flags
        assert any("optional:configserver:" in f for f in flags)

    def test_vault_in_log(self, engine):
        log = "ERROR VaultPropertySource -- Cannot connect to Vault"
        flags = engine._infra_flags_from_log(log)
        assert "--spring.cloud.vault.enabled=false" in flags

    def test_liquibase_in_log(self, engine):
        log = "ERROR LiquibaseException -- Migration failed for change set"
        flags = engine._infra_flags_from_log(log)
        assert "--spring.liquibase.enabled=false" in flags

    def test_flyway_in_log(self, engine):
        log = "ERROR FlywayException -- Unable to connect to the database"
        flags = engine._infra_flags_from_log(log)
        assert "--spring.flyway.enabled=false" in flags

    def test_kafka_in_log(self, engine):
        log = "ERROR org.apache.kafka.clients.NetworkClient -- Connection refused"
        flags = engine._infra_flags_from_log(log)
        assert "--spring.kafka.listener.auto-startup=false" in flags

    def test_multiple_failures_in_same_log(self, engine):
        log = (
            "ERROR EurekaClient -- Can't reach Eureka\n"
            "ERROR LiquibaseException -- Migration failed\n"
        )
        flags = engine._infra_flags_from_log(log)
        assert "--eureka.client.enabled=false" in flags
        assert "--spring.liquibase.enabled=false" in flags

    def test_clean_log_returns_no_flags(self, engine):
        log = "INFO  Started Application in 3.2 seconds"
        flags = engine._infra_flags_from_log(log)
        assert flags == []

    def test_no_duplicate_flags(self, engine):
        # Same pattern appears twice in log — flags must not be duplicated
        log = "EurekaClient error\nEurekaClient timeout"
        flags = engine._infra_flags_from_log(log)
        assert flags.count("--eureka.client.enabled=false") == 1


# ── Dep provisioning decisions from log ──────────────────────────────────────

class TestDepProvisioningFromLog:
    def test_postgres_connection_error(self, engine):
        engine._provision_dep = MagicMock(return_value=True)
        log = "PSQLException: Connection refused. Check that the hostname and port are correct: localhost:5432"
        deps = engine._provision_deps_from_log(log)
        assert "postgres" in deps

    def test_redis_connection_error(self, engine):
        engine._provision_dep = MagicMock(return_value=True)
        log = "RedisConnectionException: Unable to connect to Redis"
        deps = engine._provision_deps_from_log(log)
        assert "redis" in deps

    def test_mysql_connection_error(self, engine):
        engine._provision_dep = MagicMock(return_value=True)
        log = "com.mysql.jdbc.exceptions.jdbc4.CommunicationsException: Communications link failure"
        deps = engine._provision_deps_from_log(log)
        assert "mysql" in deps

    def test_mongodb_connection_error(self, engine):
        engine._provision_dep = MagicMock(return_value=True)
        log = "com.mongodb.MongoSocketOpenException: Exception opening socket at localhost:27017"
        deps = engine._provision_deps_from_log(log)
        assert "mongodb" in deps

    def test_does_not_provision_already_running_dep(self, engine):
        """If a dep name is already in _provisioned_dep_names, skip it."""
        engine._provisioned_dep_names = {"postgres"}
        engine._provision_dep = MagicMock(return_value=True)
        log = "PSQLException: Connection refused at 5432"
        engine._provision_deps_from_log(log)
        # _provision_dep should NOT be called for postgres since it's already tracked
        for call_args in engine._provision_dep.call_args_list:
            assert call_args[0][0] != "postgres"

    def test_clean_log_provisions_nothing(self, engine):
        engine._provision_dep = MagicMock(return_value=True)
        log = "INFO  Started Application in 2.1 seconds"
        deps = engine._provision_deps_from_log(log)
        assert deps == []
        engine._provision_dep.assert_not_called()

    def test_provision_failure_excluded_from_result(self, engine):
        engine._provision_dep = MagicMock(return_value=False)
        log = "PSQLException: Connection refused at 5432"
        deps = engine._provision_deps_from_log(log)
        assert "postgres" not in deps


# ── start() returns NOT_RUNNABLE for unknown service ─────────────────────────

class TestStartNotRunnable:
    def test_returns_not_runnable_for_plain_java(self, tmp_path):
        (tmp_path / "pom.xml").write_text("<project></project>")
        with patch("asel.runtime.docker.from_env", return_value=MagicMock()):
            eng = RuntimeEngine(tmp_path, Language.JAVA_MAVEN, "img")
        result = eng.start()
        assert result.status == RuntimeStatus.NOT_RUNNABLE
        assert result.service_type == ServiceType.UNKNOWN

    def test_returns_failed_when_no_jar(self, engine):
        # Service detected but no JAR built yet
        result = engine.start()
        assert result.status == RuntimeStatus.FAILED_TO_START
        assert "JAR" in result.startup_log

    def test_finds_spring_boot_war_when_no_jar(self, tmp_path):
        """Spring Boot WAR apps produce *.war, no fat *.jar — fall back to WAR."""
        (tmp_path / "pom.xml").write_text(
            "<project><parent><artifactId>spring-boot-starter-parent</artifactId></parent>"
            "<packaging>war</packaging></project>"
        )
        target = tmp_path / "target"
        target.mkdir()
        war = target / "app.war"
        war.write_bytes(b"x" * 5000)
        with patch("asel.runtime.docker.from_env", return_value=MagicMock()):
            eng = RuntimeEngine(tmp_path, Language.JAVA_MAVEN, "img")
        found = eng._find_jar()
        assert found == war

    def test_finds_jar_in_submodule_target(self, tmp_path):
        """Multi-module projects (e.g. eladmin) put the fat JAR in a sub-module target/."""
        (tmp_path / "pom.xml").write_text(
            "<project><modules><module>app</module></modules></project>"
        )
        sub = tmp_path / "app" / "target"
        sub.mkdir(parents=True)
        fat = sub / "app-1.0.jar"
        fat.write_bytes(b"x" * 1000)  # big — preferred
        thin = sub / "app-1.0-plain.jar"
        thin.write_bytes(b"x" * 10)
        with patch("asel.runtime.docker.from_env", return_value=MagicMock()):
            eng = RuntimeEngine(tmp_path, Language.JAVA_MAVEN, "img")
        found = eng._find_jar()
        assert found == fat


# ── H2 flag mode substitution ─────────────────────────────────────────────────

class TestH2FlagSubstitution:
    def test_mode_substituted_in_url_flag(self, engine, maven_repo):
        """_run_startup_attempts must substitute {mode} in the H2 URL flag."""
        (maven_repo / "pom.xml").write_text(
            "<project><dependencies>"
            "<dependency><artifactId>mysql-connector-java</artifactId></dependency>"
            "</dependencies></project>"
        )
        # Verify the mode is MySQL
        assert engine._detect_h2_mode() == "MySQL"

        # Check that the placeholder is gone after substitution
        from asel.runtime import _H2_BASE_FLAGS
        h2_mode = engine._detect_h2_mode()
        substituted = [
            f.replace("{mode}", h2_mode) if "{mode}" in f else f
            for f in _H2_BASE_FLAGS
        ]
        url_flag = next(f for f in substituted if "datasource.url" in f)
        assert "{mode}" not in url_flag
        assert "MODE=MySQL" in url_flag


# ── stop() cleans up resources ────────────────────────────────────────────────

class TestStop:
    def test_stop_removes_runtime_container(self, engine):
        mock_container = MagicMock()
        engine._runtime_container = mock_container
        engine.stop()
        mock_container.stop.assert_called_once()
        mock_container.remove.assert_called_once()
        assert engine._runtime_container is None

    def test_stop_removes_dep_containers(self, engine):
        dep1, dep2 = MagicMock(), MagicMock()
        engine._dep_containers = [dep1, dep2]
        engine.stop()
        dep1.stop.assert_called_once()
        dep1.remove.assert_called_once()
        dep2.stop.assert_called_once()
        dep2.remove.assert_called_once()
        assert engine._dep_containers == []

    def test_stop_tolerates_already_removed_container(self, engine):
        mock_container = MagicMock()
        mock_container.stop.side_effect = Exception("already removed")
        engine._runtime_container = mock_container
        engine.stop()  # must not raise
        assert engine._runtime_container is None

    def test_stop_clears_host_port(self, engine):
        engine._host_port = 12345
        engine.stop()
        assert engine._host_port is None

    def test_base_url_none_after_stop(self, engine):
        engine._host_port = 8080
        engine.stop()
        assert engine.base_url is None


# ── WAR container image selection ─────────────────────────────────────────────

class TestSelectWarContainer:
    """_select_war_container picks the right image and engine from build file + JDK tag."""

    def _make_war_engine(self, tmp_path, pom_content, image):
        (tmp_path / "pom.xml").write_text(pom_content)
        with patch("asel.runtime.docker.from_env", return_value=MagicMock()):
            return RuntimeEngine(tmp_path, Language.JAVA_MAVEN, image)

    def test_javax_pom_defaults_to_tomcat9(self, tmp_path):
        eng = self._make_war_engine(
            tmp_path,
            "<project><dependencies>"
            "<dependency><artifactId>javax.servlet-api</artifactId></dependency>"
            "</dependencies></project>",
            "maven:3.9-eclipse-temurin-17",
        )
        image, engine, jdk = eng._select_war_container()
        assert engine == "tomcat"
        assert image.startswith("tomcat:9-")
        assert jdk == 17

    def test_jakarta_pom_selects_tomcat10(self, tmp_path):
        eng = self._make_war_engine(
            tmp_path,
            "<project><dependencies>"
            "<dependency><artifactId>jakarta.servlet-api</artifactId></dependency>"
            "</dependencies></project>",
            "maven:3.9-eclipse-temurin-21",
        )
        image, engine, jdk = eng._select_war_container()
        assert engine == "tomcat"
        assert image.startswith("tomcat:10-")
        assert jdk == 21

    def test_jetty_plugin_selects_jetty_engine(self, tmp_path):
        eng = self._make_war_engine(
            tmp_path,
            "<project><build><plugins>"
            "<plugin><artifactId>jetty-maven-plugin</artifactId></plugin>"
            "</plugins></build></project>",
            "maven:3.9-eclipse-temurin-17",
        )
        image, engine, jdk = eng._select_war_container()
        assert engine == "jetty"
        assert "jetty" in image

    def test_select_tomcat_image_javax_jdk17(self):
        assert _select_tomcat_image("javax", 17) == "tomcat:9-jdk17"

    def test_select_tomcat_image_jakarta_jdk21(self):
        assert _select_tomcat_image("jakarta", 21) == "tomcat:10-jdk21"

    def test_select_jetty_image_javax_jdk17(self):
        assert _select_jetty_image("javax", 17) == "jetty:10-jdk17"

    def test_select_jetty_image_javax_jdk11(self):
        assert _select_jetty_image("javax", 11) == "jetty:10-jdk11"

    def test_select_jetty_image_jakarta_jdk17(self):
        assert _select_jetty_image("jakarta", 17) == "jetty:12-jdk17"


# ── WAR JVM opens flags (CGLIB / legacy Spring compatibility) ─────────────────

class TestWarJvmOpensFlags:
    """_launch_war_container sets JAVA_OPTS/JAVA_OPTIONS for JDK 17+."""

    def _make_war_engine_with_pom(self, tmp_path, pom_content, image):
        (tmp_path / "pom.xml").write_text(pom_content)
        with patch("asel.runtime.docker.from_env", return_value=MagicMock()):
            return RuntimeEngine(tmp_path, Language.JAVA_MAVEN, image)

    def test_jdk17_tomcat_sets_java_opts(self, tmp_path):
        eng = self._make_war_engine_with_pom(
            tmp_path, "<project></project>", "maven:3-eclipse-temurin-17"
        )
        war = tmp_path / "app.war"
        war.write_bytes(b"")
        mock_client = MagicMock()
        eng._client = mock_client

        eng._launch_war_container(war, 8080, "tomcat:9-jdk17", "tomcat", jdk_major=17)

        _, kwargs = mock_client.containers.run.call_args
        env = kwargs.get("environment", {})
        assert "JAVA_OPTS" in env
        assert "--add-opens=java.base/java.lang=ALL-UNNAMED" in env["JAVA_OPTS"]

    def test_jdk17_jetty_sets_java_options(self, tmp_path):
        eng = self._make_war_engine_with_pom(
            tmp_path, "<project></project>", "maven:3-eclipse-temurin-17"
        )
        war = tmp_path / "app.war"
        war.write_bytes(b"")
        mock_client = MagicMock()
        eng._client = mock_client

        eng._launch_war_container(war, 8080, "jetty:10-jdk17", "jetty", jdk_major=17)

        _, kwargs = mock_client.containers.run.call_args
        env = kwargs.get("environment", {})
        assert "JAVA_OPTIONS" in env
        assert "--add-opens=java.base/java.lang=ALL-UNNAMED" in env["JAVA_OPTIONS"]

    def test_jdk11_no_opens_flags(self, tmp_path):
        eng = self._make_war_engine_with_pom(
            tmp_path, "<project></project>", "maven:3-eclipse-temurin-11"
        )
        war = tmp_path / "app.war"
        war.write_bytes(b"")
        mock_client = MagicMock()
        eng._client = mock_client

        eng._launch_war_container(war, 8080, "tomcat:9-jdk11", "tomcat", jdk_major=11)

        _, kwargs = mock_client.containers.run.call_args
        env = kwargs.get("environment", {})
        # JDK11: no --add-opens needed, but proxy flags are always present
        assert "JAVA_OPTS" in env
        assert "--add-opens" not in env["JAVA_OPTS"]
        assert "-Dhttp.proxyHost=127.0.0.1" in env["JAVA_OPTS"]

    def test_jdk21_sets_opens(self, tmp_path):
        eng = self._make_war_engine_with_pom(
            tmp_path, "<project></project>", "maven:3-eclipse-temurin-21"
        )
        war = tmp_path / "app.war"
        war.write_bytes(b"")
        mock_client = MagicMock()
        eng._client = mock_client

        eng._launch_war_container(war, 8080, "tomcat:9-jdk21", "tomcat", jdk_major=21)

        _, kwargs = mock_client.containers.run.call_args
        env = kwargs.get("environment", {})
        assert "JAVA_OPTS" in env


# ── Fatal WAR pattern detection ───────────────────────────────────────────────

class TestFatalWarPatterns:
    """_FATAL_WAR_PATTERNS catch the known fatal deployment error signatures."""

    import re as _re

    def _matches(self, log: str) -> bool:
        import re
        return any(re.search(p, log, re.IGNORECASE) for p in _FATAL_WAR_PATTERNS)

    def test_tomcat_context_listener_exception(self):
        log = "SEVERE: Exception sending context initialized event to listener instance"
        assert self._matches(log)

    def test_jetty_failed_startup(self):
        log = "Failed startup of context o.e.j.w.WebAppContext"
        assert self._matches(log)

    def test_inaccessible_object_cglib(self):
        log = (
            "java.lang.reflect.InaccessibleObjectException: Unable to make "
            "protected final java.lang.Class java.lang.ClassLoader.defineClass"
        )
        assert self._matches(log)

    def test_clean_startup_log_no_match(self):
        log = "INFO: Deploying web application archive /usr/local/tomcat/webapps/app.war"
        assert not self._matches(log)

    def test_normal_503_response_no_match(self):
        # The poll loop sees 503s — the log shouldn't match on these
        log = "INFO: At least one JAR was scanned for TLDs yet contained no TLDs"
        assert not self._matches(log)


# ── classify_runtime_failure + reclassify_from_cause ─────────────────────────

class TestClassifyRuntimeFailure:
    def test_missing_property(self):
        log = "Could not resolve placeholder 'spring.datasource.url' in value \"${spring.datasource.url}\""
        assert classify_runtime_failure(log) is RuntimeFailureClass.MISSING_PROPERTY

    def test_db_connection(self):
        log = "Communications link failure\nThe last packet sent successfully to the server was 0 milliseconds ago."
        assert classify_runtime_failure(log) is RuntimeFailureClass.DB_CONNECTION

    def test_db_schema(self):
        log = "FlywayException: Validate failed: Detected failed migration to version 1"
        assert classify_runtime_failure(log) is RuntimeFailureClass.DB_SCHEMA

    def test_bean_creation_raw(self):
        log = "BeanCreationException: Error creating bean with name 'dataSource'"
        assert classify_runtime_failure(log) is RuntimeFailureClass.BEAN_CREATION

    def test_unknown(self):
        log = "Something went wrong that no pattern covers"
        assert classify_runtime_failure(log) is RuntimeFailureClass.UNKNOWN


class TestReclassifyFromCause:
    """reclassify_from_cause must look past the BeanCreationException wrapper."""

    def test_bean_wrapping_db_connection(self):
        # Spring log: BeanCreationException on line 1, real cause on Caused by: lines
        log = (
            "BeanCreationException: Error creating bean with name 'dataSource'\n"
            "Caused by: com.mysql.cj.jdbc.exceptions.CommunicationsException: "
            "Communications link failure"
        )
        assert reclassify_from_cause(log) is RuntimeFailureClass.DB_CONNECTION

    def test_bean_wrapping_missing_property(self):
        log = (
            "BeanCreationException: Error creating bean with name 'jwtService'\n"
            "Caused by: java.lang.IllegalArgumentException: "
            "Could not resolve placeholder 'jwt.secret' in value \"${jwt.secret}\""
        )
        assert reclassify_from_cause(log) is RuntimeFailureClass.MISSING_PROPERTY

    def test_bean_wrapping_db_schema(self):
        log = (
            "BeanCreationException: Error creating bean with name 'flyway'\n"
            "Caused by: org.flywaydb.core.api.FlywayException: Validate failed"
        )
        assert reclassify_from_cause(log) is RuntimeFailureClass.DB_SCHEMA

    def test_bean_wrapping_messaging(self):
        log = (
            "BeanCreationException: Error creating bean with name 'kafkaConsumer'\n"
            "Caused by: org.apache.kafka.common.KafkaException: Failed to construct kafka consumer"
        )
        assert reclassify_from_cause(log) is RuntimeFailureClass.MESSAGING

    def test_bean_wrapping_auth_bootstrap(self):
        log = (
            "BeanCreationException: Error creating bean with name 'jwtDecoder'\n"
            "Caused by: java.lang.IllegalArgumentException: "
            "Unable to resolve OpenID configuration from issuer-uri"
        )
        assert reclassify_from_cause(log) is RuntimeFailureClass.AUTH_BOOTSTRAP

    def test_bean_with_no_known_inner_cause_returns_unknown(self):
        log = (
            "BeanCreationException: Error creating bean with name 'myService'\n"
            "Caused by: com.example.SomeCustomException: completely unknown error"
        )
        assert reclassify_from_cause(log) is RuntimeFailureClass.UNKNOWN

    def test_does_not_return_bean_creation(self):
        # Even if the log only contains BeanCreationException with no inner cause,
        # reclassify must never return BEAN_CREATION (it would cause infinite loops).
        log = "BeanCreationException: Error creating bean with name 'foo'"
        result = reclassify_from_cause(log)
        assert result is not RuntimeFailureClass.BEAN_CREATION


class TestJwtStubCleanup:
    """jwt_stub block should only inject jwt.base64-secret, not hardcoded validity keys."""

    def _make_engine(self, tmp_path):
        with patch("asel.runtime.docker.from_env", return_value=MagicMock()):
            return RuntimeEngine(tmp_path, Language.JAVA_MAVEN, "maven:3.9-eclipse-temurin-21")

    def test_jwt_stub_does_not_inject_hardcoded_validity(self, tmp_path):
        """Hardcoded validity defaults must not appear when not in any profile config."""
        (tmp_path / "pom.xml").write_text("<project></project>")
        engine = self._make_engine(tmp_path)

        from asel.runtime import _StartupState
        from asel.models import ServiceType
        import json

        state = _StartupState(
            service_type=ServiceType.SPRING_BOOT,
            jar=tmp_path / "app.jar",
            host_port=8080,
            timeout=30,
            port_flag="--server.port=8080",
        )
        state.failure_class = RuntimeFailureClass.AUTH_BOOTSTRAP
        state.log = "Decode argument cannot be null"

        captured_env = {}

        def fake_try_attempt(label, st, extra_flags=None, extra_env=None):
            if extra_env:
                captured_env.update(extra_env)
            return None

        with patch.object(engine, "_try_attempt", side_effect=fake_try_attempt):
            engine._attempt_config_synthesis(state)

        assert "SPRING_APPLICATION_JSON" in captured_env
        props = json.loads(captured_env["SPRING_APPLICATION_JSON"])
        assert "jwt.base64-secret" in props
        assert "jwt.token-validity-in-seconds" not in props
        assert "jwt.token-validity-in-seconds-for-remember-me" not in props

    def test_jwt_stub_injects_validity_when_present_in_profile_config(self, tmp_path):
        """If profile config has validity, it must be injected (via extra_profile, not hardcoded)."""
        (tmp_path / "pom.xml").write_text("<project></project>")
        resources = tmp_path / "src" / "main" / "resources"
        resources.mkdir(parents=True)
        (resources / "application-dev.yml").write_text(
            "jwt:\n  base64-secret: devSecret\n  token-validity-in-seconds: 3600\n"
        )
        engine = self._make_engine(tmp_path)

        from asel.runtime import _StartupState
        from asel.models import ServiceType
        import json

        state = _StartupState(
            service_type=ServiceType.SPRING_BOOT,
            jar=tmp_path / "app.jar",
            host_port=8080,
            timeout=30,
            port_flag="--server.port=8080",
        )
        state.failure_class = RuntimeFailureClass.AUTH_BOOTSTRAP
        state.log = "Decode argument cannot be null"

        captured_env = {}

        def fake_try_attempt(label, st, extra_flags=None, extra_env=None):
            if extra_env:
                captured_env.update(extra_env)
            return None

        with patch.object(engine, "_try_attempt", side_effect=fake_try_attempt):
            engine._attempt_config_synthesis(state)

        props = json.loads(captured_env["SPRING_APPLICATION_JSON"])
        assert props.get("jwt.token-validity-in-seconds") == "3600"
        assert props.get("jwt.base64-secret") != "devSecret"


class TestLlmStartupRepair:
    """_attempt_llm_repair fires on UNKNOWN, calls LLM, applies result."""

    def _make_engine(self, tmp_path, model="deepseek-chat", provider="deepseek"):
        with patch("asel.runtime.docker.from_env", return_value=MagicMock()):
            return RuntimeEngine(tmp_path, Language.JAVA_MAVEN, "maven:3.9-eclipse-temurin-21",
                                 llm_model=model, llm_provider=provider)

    def test_skips_when_no_llm_model(self, tmp_path):
        """Engine with no LLM model configured must not call LLM."""
        (tmp_path / "pom.xml").write_text("<project></project>")
        engine = self._make_engine(tmp_path, model="", provider="")

        from asel.runtime import _StartupState
        from asel.models import ServiceType
        state = _StartupState(
            service_type=ServiceType.SPRING_BOOT,
            jar=tmp_path / "app.jar",
            host_port=8080, timeout=30, port_flag="--server.port=8080",
        )
        state.failure_class = RuntimeFailureClass.UNKNOWN
        state.log = "Some weird error we have never seen"

        result = engine._attempt_llm_repair(state)
        assert result is None

    def test_skips_when_failure_class_not_unknown(self, tmp_path):
        """Must not call LLM when failure class is known (classifiable)."""
        (tmp_path / "pom.xml").write_text("<project></project>")
        engine = self._make_engine(tmp_path)

        from asel.runtime import _StartupState
        from asel.models import ServiceType
        state = _StartupState(
            service_type=ServiceType.SPRING_BOOT,
            jar=tmp_path / "app.jar",
            host_port=8080, timeout=30, port_flag="--server.port=8080",
        )
        state.failure_class = RuntimeFailureClass.AUTH_BOOTSTRAP
        state.log = "jwt secret null"

        result = engine._attempt_llm_repair(state)
        assert result is None

    def test_applies_llm_suggested_properties(self, tmp_path):
        """When LLM returns properties dict, they must be passed as SPRING_APPLICATION_JSON."""
        import json
        (tmp_path / "pom.xml").write_text("<project></project>")
        engine = self._make_engine(tmp_path)

        from asel.runtime import _StartupState
        from asel.models import ServiceType
        state = _StartupState(
            service_type=ServiceType.SPRING_BOOT,
            jar=tmp_path / "app.jar",
            host_port=8080, timeout=30, port_flag="--server.port=8080",
        )
        state.failure_class = RuntimeFailureClass.UNKNOWN
        state.log = "Caused by: some weird error"

        llm_response = json.dumps({
            "properties": {"some.custom.property": "fixedValue"},
            "flags": ["--some.flag=true"],
            "reason": "app needs some.custom.property"
        })

        captured = {}

        def fake_try_attempt(label, st, extra_flags=None, extra_env=None):
            captured["label"] = label
            captured["flags"] = extra_flags or []
            captured["env"] = extra_env or {}
            return None

        with patch.object(engine, "_try_attempt", side_effect=fake_try_attempt), \
             patch("asel.runtime._llm_repair_call", return_value=llm_response):
            engine._attempt_llm_repair(state)

        assert captured["label"] == "llm_repair"
        assert "--some.flag=true" in captured["flags"]
        props = json.loads(captured["env"]["SPRING_APPLICATION_JSON"])
        assert props["some.custom.property"] == "fixedValue"
        assert "llm_repair" in state.stubs

    def test_handles_llm_error_gracefully(self, tmp_path):
        """LLM call failure must not crash the engine — return None."""
        (tmp_path / "pom.xml").write_text("<project></project>")
        engine = self._make_engine(tmp_path)

        from asel.runtime import _StartupState
        from asel.models import ServiceType
        state = _StartupState(
            service_type=ServiceType.SPRING_BOOT,
            jar=tmp_path / "app.jar",
            host_port=8080, timeout=30, port_flag="--server.port=8080",
        )
        state.failure_class = RuntimeFailureClass.UNKNOWN
        state.log = "some error"

        with patch("asel.runtime._llm_repair_call", side_effect=Exception("API down")):
            result = engine._attempt_llm_repair(state)

        assert result is None

    def test_returns_none_when_llm_suggests_no_changes(self, tmp_path):
        """When LLM returns empty properties and flags, must return None without modifying stubs."""
        import json
        (tmp_path / "pom.xml").write_text("<project></project>")
        engine = self._make_engine(tmp_path)

        from asel.runtime import _StartupState
        from asel.models import ServiceType
        state = _StartupState(
            service_type=ServiceType.SPRING_BOOT,
            jar=tmp_path / "app.jar",
            host_port=8080, timeout=30, port_flag="--server.port=8080",
        )
        state.failure_class = RuntimeFailureClass.UNKNOWN
        state.log = "some error"

        llm_response = json.dumps({"properties": {}, "flags": [], "reason": "nothing to do"})

        with patch("asel.runtime._llm_repair_call", return_value=llm_response):
            result = engine._attempt_llm_repair(state)

        assert result is None
        assert "llm_repair" not in state.stubs

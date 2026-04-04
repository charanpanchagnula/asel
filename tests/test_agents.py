# tests/test_agents.py
from pathlib import Path
from unittest.mock import patch, MagicMock
from asel.agents import create_build_agent, create_remediation_agent


def test_build_agent_is_created(tmp_path):
    env = MagicMock()
    agent = create_build_agent(env, tmp_path, model_id="deepseek-chat", provider="deepseek")
    assert agent is not None


def test_remediation_agent_is_created(tmp_path):
    agent = create_remediation_agent(tmp_path, model_id="deepseek-chat", provider="deepseek")
    assert agent is not None


def test_build_agent_tools_include_run_maven(tmp_path):
    env = MagicMock()
    agent = create_build_agent(env, tmp_path, model_id="deepseek-chat", provider="deepseek")
    tool_names = [t.name for t in agent.tools]
    assert "run_maven" in tool_names


def test_remediation_agent_tools_include_edit_file(tmp_path):
    agent = create_remediation_agent(tmp_path, model_id="deepseek-chat", provider="deepseek")
    tool_names = [t.name for t in agent.tools]
    assert "edit_file" in tool_names


def test_build_agent_run_maven_tool_calls_env(tmp_path):
    env = MagicMock()
    env.run.return_value = (0, "BUILD SUCCESS")
    agent = create_build_agent(env, tmp_path, model_id="deepseek-chat", provider="deepseek")
    run_maven_tool = next(t for t in agent.tools if t.name == "run_maven")
    result = run_maven_tool.entrypoint(args="clean install -DskipTests")
    env.run.assert_called_once_with(["mvn", "clean", "install", "-DskipTests"])
    assert "BUILD SUCCESS" in result


def test_edit_file_tool_modifies_file(tmp_path):
    pom = tmp_path / "pom.xml"
    pom.write_text("<version>1.0</version>")
    agent = create_remediation_agent(tmp_path, model_id="deepseek-chat", provider="deepseek")
    edit_tool = next(t for t in agent.tools if t.name == "edit_file")
    result = edit_tool.entrypoint(
        path="pom.xml",
        old_text="<version>1.0</version>",
        new_text="<version>2.0</version>",
    )
    assert pom.read_text() == "<version>2.0</version>"
    assert "pom.xml" in result

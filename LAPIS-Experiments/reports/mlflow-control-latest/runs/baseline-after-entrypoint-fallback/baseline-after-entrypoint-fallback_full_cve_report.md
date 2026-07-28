# LAPIS Full-CVE YASA Report

- Label: `baseline-after-entrypoint-fallback`
- Case: `cve-2023-4033-mlflow`
- Status: `reported`
- Result: `finding`
- Return code: `0`
- Tool: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Tool`
- Source path: `/home/ubuntu/llm-yasa-repair/py-bench/cve-2023-4033-mlflow`
- Rule: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/cases/control/cve-2023-4033-mlflow/rules/final-sink-only.json`
- CTPC: `None`
- Report dir: `/home/ubuntu/llm-yasa-repair/LAPIS/LAPIS-Experiments/reports/mlflow-control-latest/runs/baseline-after-entrypoint-fallback/baseline-after-entrypoint-fallback`

## Summary

- Findings: `4`
- Sources marked: `1`
- Sinks matched: `46`
- Entry points: `1`
- Files analyzed: `413`
- Lines analyzed: `103168`

## Trace Quality

- Trace status: `reported_trace`
- CCEC virtual sink: `False`
- CTPC fact trace: `False`
- FACT TRACE GAP: `False`
- Needs CTPC: `False`
- Needs trace review: `False`

## Interpretation

This is a full original-CVE run. A finding here is evidence that the enhanced analyzer connected the case entrypoint, interprocedural execution context, CTPC access-path facts, and final sink rule on the original dataset.

## Findings

```text
Finding 1
  sinkRule: subprocess.Popen
  sinkAttribute: PythonCommandInjection
  primary: /home/ubuntu/llm-yasa-repair/py-bench/cve-2023-4033-mlflow/mlflow/utils/process.py:95:15
  Step 0: file:///mlflow/models/cli.py:133:5
    node: input_path
    snippet:
       /mlflow/models/cli.py
        AffectedNodeName: input_path
        133: SOURCE:      input_path,
  Step 1: file:///mlflow/models/cli.py:149:9
    node: input_path
    snippet:
       /mlflow/models/cli.py
        AffectedNodeName: input_path
        149: Var Pass:          input_path=input_path,
  Step 2: file:///mlflow/models/cli.py:145:12
    node: predict
    snippet:
       /mlflow/models/cli.py
        AffectedNodeName: predict
        145: CALL:      return get_flavor_backend(
        146: CALL:          model_uri, env_manager=env_manager, install_mlflow=install_mlflow
        147: CALL:      ).predict(
        148: CALL:          model_uri=model_uri,
        149: CALL:          input_path=input_path,
        150: CALL:          output_path=output_path,
        151: CALL:          content_type=content_type,
        152: CALL:      )
  Step 3: file:///mlflow/pyfunc/backend.py:134:23
    node: input_path
    snippet:
       /mlflow/pyfunc/backend.py
        AffectedNodeName: input_path
        134: ARG PASS:      def predict(self, model_uri, input_path, output_path, content_type):
  Step 4: file:///mlflow/pyfunc/backend.py:155:17
    node: input_path
    snippet:
       /mlflow/pyfunc/backend.py
        AffectedNodeName: input_path
        155: Var Pass:                  input_path=repr(input_path),
  Step 5: file:///mlflow/pyfunc/backend.py:146:13
    node: command
    snippet:
       /mlflow/pyfunc/backend.py
        AffectedNodeName: command
        146: Var Pass:              command = (
        147: Var Pass:                  'python -c "from mlflow.pyfunc.scoring_server import _predict; _predict('
        148: Var Pass:                  "model_uri={model_uri}, "
        149: Var Pass:                  "input_path={input_path}, "
        150: Var Pass:                  "output_path={output_path}, "
        151: Var Pass:                  "content_type={content_type})"
        152: Var Pass:                  '"'
        153: Var Pass:              ).format(
        154: Var Pass:                  model_uri=repr(local_uri),
        155: Var Pass:                  input_path=repr(input_path),
        156: Var Pass:                  output_path=repr(output_path),
        157: Var Pass:                  content_type=repr(content_type),
        158: Var Pass:              )
  Step 6: file:///mlflow/pyfunc/backend.py:159:20
    node: execute
    snippet:
       /mlflow/pyfunc/backend.py
        AffectedNodeName: execute
        159: CALL:              return self.prepare_env(local_path).execute(command)
  Step 7: file:///mlflow/utils/environment.py:589:9
    node: command
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: command
        589: ARG PASS:          command,
  Step 8: file:///mlflow/utils/environment.py:602:13
    node: command
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: command
        602: Var Pass:              command = [command]
  Step 9: file:///mlflow/utils/environment.py:609:9
    node: command
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: command
        609: Var Pass:          command = separator.join(map(str, self._activate_cmd + command))
  Step 10: file:///mlflow/utils/environment.py:611:13
    node: command
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: command
        611: Var Pass:              command = ["bash", "-c", command]
  Step 11: file:///mlflow/utils/environment.py:613:13
    node: command
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: command
        613: Var Pass:              command = ["cmd", "/c", command]
  Step 12: file:///mlflow/utils/environment.py:615:16
    node: _exec_cmd
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: _exec_cmd
        615: CALL:          return _exec_cmd(
        616: CALL:              command,
        617: CALL:              env=command_env,
        618: CALL:              capture_output=capture_output,
        619: CALL:              synchronous=synchronous,
        620: CALL:              preexec_fn=preexec_fn,
        621: CALL:              close_fds=True,
        622: CALL:              stdout=stdout,
        623: CALL:              stderr=stderr,
        624: CALL:              stdin=stdin,
        625: CALL:          )
  Step 13: file:///mlflow/utils/process.py:32:5
    node: cmd
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: cmd
        32:  ARG PASS:      cmd,
  Step 14: file:///mlflow/utils/process.py:79:9
    node: cmd
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: cmd
        79:  Var Pass:          cmd = list(map(str, cmd))
  Step 15: file:///mlflow/utils/process.py:95:5
    node: process
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: process
        95:  Var Pass:      process = subprocess.Popen(
        96:  Var Pass:          cmd,
        97:  Var Pass:          env=env,
        98:  Var Pass:          text=True,
        99:  Var Pass:          **kwargs,
        100: Var Pass:      )
  Step 16: file:///mlflow/utils/process.py:102:9
    node: [return value]
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: [return value]
        102: Return Value:          return process
  Step 17: file:///mlflow/utils/process.py:108:5
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: [object Object],[object Object]
        108: Var Pass:      stdout, stderr = process.communicate()
  Step 18: file:///mlflow/utils/process.py:109:5
    node: returncode
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: returncode
        109: Var Pass:      returncode = process.poll()
  Step 19: file:///mlflow/utils/process.py:112:9
    node: returncode
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: returncode
        112: Var Pass:          returncode=returncode,
  Step 20: file:///mlflow/utils/process.py:113:9
    node: stdout
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: stdout
        113: Var Pass:          stdout=stdout,
  Step 21: file:///mlflow/utils/process.py:114:9
    node: stderr
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: stderr
        114: Var Pass:          stderr=stderr,
  Step 22: file:///mlflow/utils/process.py:110:5
    node: comp_process
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: comp_process
        110: Var Pass:      comp_process = subprocess.CompletedProcess(
        111: Var Pass:          process.args,
        112: Var Pass:          returncode=returncode,
        113: Var Pass:          stdout=stdout,
        114: Var Pass:          stderr=stderr,
        115: Var Pass:      )
  Step 23: file:///mlflow/utils/process.py:12:9
    node: lines
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: lines
        12:  Var Pass:          lines = [
        13:  Var Pass:              f"Non-zero exit code: {process.returncode}",
        14:  Var Pass:              f"Command: {process.args}",
        15:  Var Pass:          ]
  Step 24: file:///mlflow/utils/process.py:17:13
    node: lines
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: lines
        17:  Var Pass:              lines += [
        18:  Var Pass:                  "",
        19:  Var Pass:                  "STDOUT:",
        20:  Var Pass:                  process.stdout,
        21:  Var Pass:              ]
  Step 25: file:///mlflow/utils/process.py:23:13
    node: lines
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: lines
        23:  Var Pass:              lines += [
        24:  Var Pass:                  "",
        25:  Var Pass:                  "STDERR:",
        26:  Var Pass:                  process.stderr,
        27:  Var Pass:              ]
  Step 26: file:///mlflow/utils/process.py:28:9
    node: [return value]
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: [return value]
        28:  Return Value:          return cls("\n".join(lines))
  Step 27: file:///mlflow/utils/process.py:11:5
    node: from_completed_process
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: from_completed_process
        11:  CALL RETURN:     def from_completed_process(cls, process):
        12:  CALL RETURN:         lines = [
        13:  CALL RETURN:             f"Non-zero exit code: {process.returncode}",
        14:  CALL RETURN:             f"Command: {process.args}",
        15:  CALL RETURN:         ]
        16:  CALL RETURN:         if process.stdout:
        17:  CALL RETURN:             lines += [
        18:  CALL RETURN:                 "",
        19:  CALL RETURN:                 "STDOUT:",
        20:  CALL RETURN:                 process.stdout,
        21:  CALL RETURN:             ]
        22:  CALL RETURN:         if process.stderr:
        23:  CALL RETURN:             lines += [
        24:  CALL RETURN:                 "",
        25:  CALL RETURN:                 "STDERR:",
        26:  CALL RETURN:                 process.stderr,
        27:  CALL RETURN:             ]
        28:  CALL RETURN:         return cls("\n".join(lines))
  Step 28: file:///mlflow/utils/process.py:118:5
    node: [return value]
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: [return value]
        118: Return Value:      return comp_process
  Step 29: file:///mlflow/utils/environment.py:615:16
    node: _exec_cmd
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: _exec_cmd
        615: CALL RETURN:         return _exec_cmd(
        616: CALL RETURN:             command,
        617: CALL RETURN:             env=command_env,
        618: CALL RETURN:             capture_output=capture_output,
        619: CALL RETURN:             synchronous=synchronous,
        620: CALL RETURN:             preexec_fn=preexec_fn,
        621: CALL RETURN:             close_fds=True,
        622: CALL RETURN:             stdout=stdout,
        623: CALL RETURN:             stderr=stderr,
        624: CALL RETURN:             stdin=stdin,
        625: CALL RETURN:         )
  Step 30: file:///mlflow/utils/environment.py:615:9
    node: [return value]
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: [return value]
        615: Return Value:          return _exec_cmd(
        616: Return Value:              command,
        617: Return Value:              env=command_env,
        618: Return Value:              capture_output=capture_output,
        619: Return Value:              synchronous=synchronous,
        620: Return Value:              preexec_fn=preexec_fn,
        621: Return Value:              close_fds=True,
        622: Return Value:              stdout=stdout,
        623: Return Value:              stderr=stderr,
        624: Return Value:              stdin=stdin,
        625: Return Value:          )
  Step 31: file:///mlflow/pyfunc/backend.py:159:20
    node: execute
    snippet:
       /mlflow/pyfunc/backend.py
        AffectedNodeName: execute
        159: CALL RETURN:             return self.prepare_env(local_path).execute(command)
  Step 32: file:///mlflow/pyfunc/backend.py:159:20
    node: execute
    snippet:
       /mlflow/pyfunc/backend.py
        AffectedNodeName: execute
        159: CALL:              return self.prepare_env(local_path).execute(command)
  Step 33: file:///mlflow/utils/environment.py:589:9
    node: command
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: command
        589: ARG PASS:          command,
  Step 34: file:///mlflow/utils/environment.py:602:13
    node: command
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: command
        602: Var Pass:              command = [command]
  Step 35: file:///mlflow/utils/environment.py:609:9
    node: command
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: command
        609: Var Pass:          command = separator.join(map(str, self._activate_cmd + command))
  Step 36: file:///mlflow/utils/environment.py:611:13
    node: command
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: command
        611: Var Pass:              command = ["bash", "-c", command]
  Step 37: file:///mlflow/utils/environment.py:613:13
    node: command
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: command
        613: Var Pass:              command = ["cmd", "/c", command]
  Step 38: file:///mlflow/utils/environment.py:615:16
    node: _exec_cmd
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: _exec_cmd
        615: CALL:          return _exec_cmd(
        616: CALL:              command,
        617: CALL:              env=command_env,
        618: CALL:              capture_output=capture_output,
        619: CALL:              synchronous=synchronous,
        620: CALL:              preexec_fn=preexec_fn,
        621: CALL:              close_fds=True,
        622: CALL:              stdout=stdout,
        623: CALL:              stderr=stderr,
        624: CALL:              stdin=stdin,
        625: CALL:          )
  Step 39: file:///mlflow/utils/process.py:32:5
    node: cmd
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: cmd
        32:  ARG PASS:      cmd,
  Step 40: file:///mlflow/utils/process.py:79:9
    node: cmd
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: cmd
        79:  Var Pass:          cmd = list(map(str, cmd))
  Step 41: file:///mlflow/utils/process.py:95:5
    node: process
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: process
        95:  Var Pass:      process = subprocess.Popen(
        96:  Var Pass:          cmd,
        97:  Var Pass:          env=env,
        98:  Var Pass:          text=True,
        99:  Var Pass:          **kwargs,
        100: Var Pass:      )
  Step 42: file:///mlflow/utils/process.py:102:9
    node: [return value]
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: [return value]
        102: Return Value:          return process
  Step 43: file:///mlflow/utils/process.py:108:5
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: [object Object],[object Object]
        108: Var Pass:      stdout, stderr = process.communicate()
  Step 44: file:///mlflow/utils/process.py:109:5
    node: returncode
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: returncode
        109: Var Pass:      returncode = process.poll()
  Step 45: file:///mlflow/utils/process.py:112:9
    node: returncode
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: returncode
        112: Var Pass:          returncode=returncode,
  Step 46: file:///mlflow/utils/process.py:113:9
    node: stdout
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: stdout
        113: Var Pass:          stdout=stdout,
  Step 47: file:///mlflow/utils/process.py:114:9
    node: stderr
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: stderr
        114: Var Pass:          stderr=stderr,
  Step 48: file:///mlflow/utils/process.py:110:5
    node: comp_process
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: comp_process
        110: Var Pass:      comp_process = subprocess.CompletedProcess(
        111: Var Pass:          process.args,
        112: Var Pass:          returncode=returncode,
        113: Var Pass:          stdout=stdout,
        114: Var Pass:          stderr=stderr,
        115: Var Pass:      )
  Step 49: file:///mlflow/utils/process.py:12:9
    node: lines
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: lines
        12:  Var Pass:          lines = [
        13:  Var Pass:              f"Non-zero exit code: {process.returncode}",
        14:  Var Pass:              f"Command: {process.args}",
        15:  Var Pass:          ]
  Step 50: file:///mlflow/utils/process.py:17:13
    node: lines
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: lines
        17:  Var Pass:              lines += [
        18:  Var Pass:                  "",
        19:  Var Pass:                  "STDOUT:",
        20:  Var Pass:                  process.stdout,
        21:  Var Pass:              ]
  Step 51: file:///mlflow/utils/process.py:23:13
    node: lines
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: lines
        23:  Var Pass:              lines += [
        24:  Var Pass:                  "",
        25:  Var Pass:                  "STDERR:",
        26:  Var Pass:                  process.stderr,
        27:  Var Pass:              ]
  Step 52: file:///mlflow/utils/process.py:28:9
    node: [return value]
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: [return value]
        28:  Return Value:          return cls("\n".join(lines))
  Step 53: file:///mlflow/utils/process.py:11:5
    node: from_completed_process
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: from_completed_process
        11:  CALL RETURN:     def from_completed_process(cls, process):
        12:  CALL RETURN:         lines = [
        13:  CALL RETURN:             f"Non-zero exit code: {process.returncode}",
        14:  CALL RETURN:             f"Command: {process.args}",
        15:  CALL RETURN:         ]
        16:  CALL RETURN:         if process.stdout:
        17:  CALL RETURN:             lines += [
        18:  CALL RETURN:                 "",
        19:  CALL RETURN:                 "STDOUT:",
        20:  CALL RETURN:                 process.stdout,
        21:  CALL RETURN:             ]
        22:  CALL RETURN:         if process.stderr:
        23:  CALL RETURN:             lines += [
        24:  CALL RETURN:                 "",
        25:  CALL RETURN:                 "STDERR:",
        26:  CALL RETURN:                 process.stderr,
        27:  CALL RETURN:             ]
        28:  CALL RETURN:         return cls("\n".join(lines))
  Step 54: file:///mlflow/utils/process.py:118:5
    node: [return value]
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: [return value]
        118: Return Value:      return comp_process
  Step 55: file:///mlflow/utils/environment.py:615:16
    node: _exec_cmd
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: _exec_cmd
        615: CALL RETURN:         return _exec_cmd(
        616: CALL RETURN:             command,
        617: CALL RETURN:             env=command_env,
        618: CALL RETURN:             capture_output=capture_output,
        619: CALL RETURN:             synchronous=synchronous,
        620: CALL RETURN:             preexec_fn=preexec_fn,
        621: CALL RETURN:             close_fds=True,
        622: CALL RETURN:             stdout=stdout,
        623: CALL RETURN:             stderr=stderr,
        624: CALL RETURN:             stdin=stdin,
        625: CALL RETURN:         )
  Step 56: file:///mlflow/utils/environment.py:615:9
    node: [return value]
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: [return value]
        615: Return Value:          return _exec_cmd(
        616: Return Value:              command,
        617: Return Value:              env=command_env,
        618: Return Value:              capture_output=capture_output,
        619: Return Value:              synchronous=synchronous,
        620: Return Value:              preexec_fn=preexec_fn,
        621: Return Value:              close_fds=True,
        622: Return Value:              stdout=stdout,
        623: Return Value:              stderr=stderr,
        624: Return Value:              stdin=stdin,
        625: Return Value:          )
  Step 57: file:///mlflow/pyfunc/backend.py:159:20
    node: execute
    snippet:
       /mlflow/pyfunc/backend.py
        AffectedNodeName: execute
        159: CALL RETURN:             return self.prepare_env(local_path).execute(command)
  Step 58: file:///mlflow/pyfunc/backend.py:159:20
    node: execute
    snippet:
       /mlflow/pyfunc/backend.py
        AffectedNodeName: execute
        159: CALL:              return self.prepare_env(local_path).execute(command)
  Step 59: file:///mlflow/utils/environment.py:589:9
    node: command
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: command
        589: ARG PASS:          command,
  Step 60: file:///mlflow/utils/environment.py:602:13
    node: command
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: command
        602: Var Pass:              command = [command]
  Step 61: file:///mlflow/utils/environment.py:609:9
    node: command
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: command
        609: Var Pass:          command = separator.join(map(str, self._activate_cmd + command))
  Step 62: file:///mlflow/utils/environment.py:611:13
    node: command
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: command
        611: Var Pass:              command = ["bash", "-c", command]
  Step 63: file:///mlflow/utils/environment.py:613:13
    node: command
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: command
        613: Var Pass:              command = ["cmd", "/c", command]
  Step 64: file:///mlflow/utils/environment.py:615:16
    node: _exec_cmd
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: _exec_cmd
        615: CALL:          return _exec_cmd(
        616: CALL:              command,
        617: CALL:              env=command_env,
        618: CALL:              capture_output=capture_output,
        619: CALL:              synchronous=synchronous,
        620: CALL:              preexec_fn=preexec_fn,
        621: CALL:              close_fds=True,
        622: CALL:              stdout=stdout,
        623: CALL:              stderr=stderr,
        624: CALL:              stdin=stdin,
        625: CALL:          )
  Step 65: file:///mlflow/utils/process.py:32:5
    node: cmd
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: cmd
        32:  ARG PASS:      cmd,
  Step 66: file:///mlflow/utils/process.py:79:9
    node: cmd
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: cmd
        79:  Var Pass:          cmd = list(map(str, cmd))
  Step 67: file:///mlflow/utils/process.py:95:5
    node: process
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: process
        95:  Var Pass:      process = subprocess.Popen(
        96:  Var Pass:          cmd,
        97:  Var Pass:          env=env,
        98:  Var Pass:          text=True,
        99:  Var Pass:          **kwargs,
        100: Var Pass:      )
  Step 68: file:///mlflow/utils/process.py:102:9
    node: [return value]
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: [return value]
        102: Return Value:          return process
  Step 69: file:///mlflow/utils/process.py:108:5
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: [object Object],[object Object]
        108: Var Pass:      stdout, stderr = process.communicate()
  Step 70: file:///mlflow/utils/process.py:109:5
    node: returncode
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: returncode
        109: Var Pass:      returncode = process.poll()
  Step 71: file:///mlflow/utils/process.py:112:9
    node: returncode
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: returncode
        112: Var Pass:          returncode=returncode,
  Step 72: file:///mlflow/utils/process.py:113:9
    node: stdout
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: stdout
        113: Var Pass:          stdout=stdout,
  Step 73: file:///mlflow/utils/process.py:114:9
    node: stderr
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: stderr
        114: Var Pass:          stderr=stderr,
  Step 74: file:///mlflow/utils/process.py:110:5
    node: comp_process
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: comp_process
        110: Var Pass:      comp_process = subprocess.CompletedProcess(
        111: Var Pass:          process.args,
        112: Var Pass:          returncode=returncode,
        113: Var Pass:          stdout=stdout,
        114: Var Pass:          stderr=stderr,
        115: Var Pass:      )
  Step 75: file:///mlflow/utils/process.py:12:9
    node: lines
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: lines
        12:  Var Pass:          lines = [
        13:  Var Pass:              f"Non-zero exit code: {process.returncode}",
        14:  Var Pass:              f"Command: {process.args}",
        15:  Var Pass:          ]
  Step 76: file:///mlflow/utils/process.py:17:13
    node: lines
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: lines
        17:  Var Pass:              lines += [
        18:  Var Pass:                  "",
        19:  Var Pass:                  "STDOUT:",
        20:  Var Pass:                  process.stdout,
        21:  Var Pass:              ]
  Step 77: file:///mlflow/utils/process.py:23:13
    node: lines
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: lines
        23:  Var Pass:              lines += [
        24:  Var Pass:                  "",
        25:  Var Pass:                  "STDERR:",
        26:  Var Pass:                  process.stderr,
        27:  Var Pass:              ]
  Step 78: file:///mlflow/utils/process.py:28:9
    node: [return value]
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: [return value]
        28:  Return Value:          return cls("\n".join(lines))
  Step 79: file:///mlflow/utils/process.py:11:5
    node: from_completed_process
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: from_completed_process
        11:  CALL RETURN:     def from_completed_process(cls, process):
        12:  CALL RETURN:         lines = [
        13:  CALL RETURN:             f"Non-zero exit code: {process.returncode}",
        14:  CALL RETURN:             f"Command: {process.args}",
        15:  CALL RETURN:         ]
        16:  CALL RETURN:         if process.stdout:
        17:  CALL RETURN:             lines += [
        18:  CALL RETURN:                 "",
        19:  CALL RETURN:                 "STDOUT:",
        20:  CALL RETURN:                 process.stdout,
        21:  CALL RETURN:             ]
        22:  CALL RETURN:         if process.stderr:
        23:  CALL RETURN:             lines += [
        24:  CALL RETURN:                 "",
        25:  CALL RETURN:                 "STDERR:",
        26:  CALL RETURN:                 process.stderr,
        27:  CALL RETURN:             ]
        28:  CALL RETURN:         return cls("\n".join(lines))
  Step 80: file:///mlflow/utils/process.py:118:5
    node: [return value]
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: [return value]
        118: Return Value:      return comp_process
  Step 81: file:///mlflow/utils/environment.py:615:16
    node: _exec_cmd
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: _exec_cmd
        615: CALL RETURN:         return _exec_cmd(
        616: CALL RETURN:             command,
        617: CALL RETURN:             env=command_env,
        618: CALL RETURN:             capture_output=capture_output,
        619: CALL RETURN:             synchronous=synchronous,
        620: CALL RETURN:             preexec_fn=preexec_fn,
        621: CALL RETURN:             close_fds=True,
        622: CALL RETURN:             stdout=stdout,
        623: CALL RETURN:             stderr=stderr,
        624: CALL RETURN:             stdin=stdin,
        625: CALL RETURN:         )
  Step 82: file:///mlflow/utils/environment.py:615:9
    node: [return value]
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: [return value]
        615: Return Value:          return _exec_cmd(
        616: Return Value:              command,
        617: Return Value:              env=command_env,
        618: Return Value:              capture_output=capture_output,
        619: Return Value:              synchronous=synchronous,
        620: Return Value:              preexec_fn=preexec_fn,
        621: Return Value:              close_fds=True,
        622: Return Value:              stdout=stdout,
        623: Return Value:              stderr=stderr,
        624: Return Value:              stdin=stdin,
        625: Return Value:          )
  Step 83: file:///mlflow/pyfunc/backend.py:159:20
    node: execute
    snippet:
       /mlflow/pyfunc/backend.py
        AffectedNodeName: execute
        159: CALL RETURN:             return self.prepare_env(local_path).execute(command)
  Step 84: file:///mlflow/pyfunc/backend.py:159:20
    node: execute
    snippet:
       /mlflow/pyfunc/backend.py
        AffectedNodeName: execute
        159: CALL:              return self.prepare_env(local_path).execute(command)
  Step 85: file:///mlflow/utils/environment.py:589:9
    node: command
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: command
        589: ARG PASS:          command,
  Step 86: file:///mlflow/utils/environment.py:602:13
    node: command
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: command
        602: Var Pass:              command = [command]
  Step 87: file:///mlflow/utils/environment.py:609:9
    node: command
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: command
        609: Var Pass:          command = separator.join(map(str, self._activate_cmd + command))
  Step 88: file:///mlflow/utils/environment.py:611:13
    node: command
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: command
        611: Var Pass:              command = ["bash", "-c", command]
  Step 89: file:///mlflow/utils/environment.py:613:13
    node: command
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: command
        613: Var Pass:              command = ["cmd", "/c", command]
  Step 90: file:///mlflow/utils/environment.py:615:16
    node: _exec_cmd
    snippet:
       /mlflow/utils/environment.py
        AffectedNodeName: _exec_cmd
        615: CALL:          return _exec_cmd(
        616: CALL:              command,
        617: CALL:              env=command_env,
        618: CALL:              capture_output=capture_output,
        619: CALL:              synchronous=synchronous,
        620: CALL:              preexec_fn=preexec_fn,
        621: CALL:              close_fds=True,
        622: CALL:              stdout=stdout,
        623: CALL:              stderr=stderr,
        624: CALL:              stdin=stdin,
        625: CALL:          )
  Step 91: file:///mlflow/utils/process.py:32:5
    node: cmd
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: cmd
        32:  ARG PASS:      cmd,
  Step 92: file:///mlflow/utils/process.py:79:9
    node: cmd
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: cmd
        79:  Var Pass:          cmd = list(map(str, cmd))
  Step 93: file:///mlflow/utils/process.py:95:15
    node: subprocess.Popen
    snippet:
       /mlflow/utils/process.py
        AffectedNodeName: subprocess.Popen
        95:  SINK:      process = subprocess.Popen(
        96:  SINK:          cmd,
        97:  SINK:          env=env,
        98:  SINK:          text=True,
        99:  SINK:          **kwargs,
        100: SINK:      )
```

## Ordered Source-To-Sink Chain

```text
Step 0: SOURCE poc/poc_cve_2023_4033_mlflow.py:15  input_path = cve_2023_4033_source() [case.source]
```

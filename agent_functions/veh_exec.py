import base64
import json
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import (
    MythicRPCFileGetContentMessage,
    SendMythicRPCFileGetContent,
)


class VehExecArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="sc",
                type=ParameterType.File,
                description="Select raw binary (.bin) file",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="debug",
                type=ParameterType.Boolean,
                description="Enable verbose debug output",
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if not self.command_line:
            return
        try:
            args_dict = json.loads(self.command_line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON command line: {exc}") from exc

        if "sc" in args_dict:
            sc_val = args_dict["sc"]
            if isinstance(sc_val, dict):
                sc_val = (
                    sc_val.get("agent_file_id")
                    or sc_val.get("AgentFileId")
                    or sc_val.get("FileID")
                    or sc_val.get("id")
                    or sc_val
                )
            self.add_arg("sc", sc_val)

        if "debug" in args_dict:
            self.add_arg("debug", bool(args_dict["debug"]))


class VehExecCommand(CommandBase):
    cmd = "veh_exec"
    needs_admin = False
    help_cmd = "veh_exec"
    description = "Shellcode execution via hardware breakpoints and VEH's"
    version = 1
    author = "0xAmir"
    argument_class = VehExecArguments
    attackmapping = []

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        raw_sc = taskData.args.get_arg("sc")
        if isinstance(raw_sc, dict):
            sc_val = (
                raw_sc.get("agent_file_id")
                or raw_sc.get("AgentFileId")
                or raw_sc.get("FileID")
                or raw_sc.get("id")
            )
        else:
            sc_val = raw_sc

        if not sc_val:
            response.Success = False
            response.Error = "Missing 'sc' argument."
            return response

        debug_flag = bool(taskData.args.get_arg("debug"))

        file_resp = await SendMythicRPCFileGetContent(
            MythicRPCFileGetContentMessage(AgentFileId=str(sc_val))
        )
        if not file_resp.Success:
            response.Success = False
            response.Error = f"MythicRPCFileGetContent failed: {file_resp.Error}"
            return response

        b64_payload = base64.b64encode(file_resp.Content).decode("utf-8")
        taskData.args.set_arg("sc", b64_payload)
        taskData.args.set_arg("debug", debug_flag)
        response.DisplayParams = f"file_id={sc_val}, bytes={len(file_resp.Content)}, debug={debug_flag}"
        return response

    async def process_response(
        self, response: PTTaskProcessResponseMessageResponse
    ) -> PTTaskProcessResponseMessageResponse:
        return response
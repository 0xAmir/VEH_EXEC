# VEH_EXEC

A C++ implementation of shellcode execution using HWBP and VEH's ported to python3 and adjusted to work with Mythic C2's Medusa Agent

## Installation
* The script within the `agent_functions` directory tells Mythic how to properties of the command (eg: arguments, cmd_name etc..). Copy the contents of the folder to `$MYTHIC_PATH/InstalledServices/medusa/medusa/mythic/agent_functions/`.
* The code within the `agent_code` directory is the actual code the command executes, copy its contents to `$MYTHIC_PATH/InstalledServices/medusa/medusa/agent_code/`.
* Restart the Medusa docker container (`mythic-cli restart medusa`).
* Create a new Medusa payload, the command `vec_exec` should now appear in the "Command Available" pane during payload creation.

## Usage
`veh_exec [-debug] -sc <local path to shellcode bin file>`

# Veracode Mitigation Rejector

Identifies and, optionally, rejects self-approved mitigations (mitigations that were proposed and approved by the same Veracode user).

## Prerequisites

Must have a Veracode user or API Service account that has generated API credentials.

The user must have the following role(s):

* Reviewer or Results API role (required)
* Mitigation Approver or Mitigation and Comments API role (optional, required to use the `--reject` switch)

## Setup

Clone this repository:

    git clone https://github.com/tjarrettveracode/veracode-mitigation-rejector

Install dependencies:

    cd veracode-mitigation-rejector
    pip install -r requirements.txt

(Optional) Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

## Run

If you have saved credentials as above you can run:

    python vcmitreject.py (arguments)

Otherwise you will need to set environment variables:

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    python vcmitreject.py (arguments)

Arguments supported include:

* `-a`, `--app_id` (opt): Application GUID for which you want to check for self-approved mitigations. If `--app_id` is not specified, the script will check for new self-approved mitigations across *all* applications that the user can access.
* `-p`, `--prompt` (opt): Prompt to check a specific application by name for self-approved mitigations
* `-n`, `--new-since` (opt): Checks for new self-approved mitigations that were approved since the date/time provided (in `YYYY-MM-DDTHH:MM:SS.OOOZ` format). If not specified, the script will check for self-approved mitigations over all time. This may run for a while!
* `-r`, `--reject` (opt): If specified, will attempt to reject any self-approved mitigations found

## Notes

1. The script ignores findings that were automatically approved by Custom Cleansers.
1. To find all self-approved mitigations in your account, you can run the script with no arguments. Please note that this may run for a long time depending on the number of applications in your environment. If running across all applications, it is recommended to provide a value for `--new-since`.

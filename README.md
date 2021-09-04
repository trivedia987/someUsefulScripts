# someUsefulScripts
## Scripts for Infra related Information as JSON

### 1. OS Data
Powershell script, needs to be run with local admin creds.
- Includes OS Related Info
- Includes Harware Info
- Windows Update Details
- Installed Application Details
- Logged In user details

##### Output Format:
#
#
> {
>        "OSSummary": <OS Related Information>,
>        "UpdateInfo": <Windows Update Related Info>,
>        "LoogedInUser": <Logged In user Related Info>,
>        "HardwareInfo": <Hardware Related Info>,
>        "AppInfo": <Installed Hardware Related Info>
>}

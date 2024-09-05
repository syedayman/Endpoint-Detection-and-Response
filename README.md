# EDR Home Lab: C2 Attack and Defence 
This project simulates an attack from a Commmand & Control (C2) server using 'Sliver' on a Windows Endpoint that utilizes the LimaCharlie EDR solution. 

[Eric Capuano's Guide](https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-part-1e0)

## Lab Environment
Attacker/C2 server - Ubuntu Server 22.04.01 iso running on VMware

Victim - Windows 11 VM with a sensor linked to LimaCharlie running on VMware

## Machines Setup
### Windows (victim)
- Disable Microsoft Defender
- Disable Tamper Protection
- Set the 'Start' value to 4 (disabled) for various registry keys
- Disable standby timeout
- Install Sysmon
- Install LimaCharlie, and install a LC sensor on the Windows endpoint
- Configure LimaCharlie to export sysmon event logs (in addition to its own EDR telemetry)

### Ubuntu (attacker)
- Set static IP
- Install OpenSSH server (for easy clipboard access on host)
- SSH into the system and install Sliver

## Generating payload
Generate the C2 payload 

![Screenshot 2024-09-05 153304](https://github.com/user-attachments/assets/44d260ea-01f1-41c6-a3f0-f7c4aee590b6)

Host a simple python webserver in the same directory using `python3 -m http.server 80` to download the file on the victim machine

Start the sliver server listener and execute the payload on the victim machine in an administrative level shell

![Screenshot 2024-09-05 153323](https://github.com/user-attachments/assets/d0882e36-497f-4104-8611-6d32a40fdc65)

Verify the session, and use the command `use [session-id]` to interact with the C2 session, and now we can run commands on the host

![Screenshot 2024-09-05 153528](https://github.com/user-attachments/assets/4116b11b-e734-4da7-b6a8-b34e33841a5c)

## Observing EDR Telemetry
Select the active Windows sensor on LimaCharlie and select 'Processes' in the left menu, where the active unsigned implant is visible

![Screenshot 2024-09-05 153943](https://github.com/user-attachments/assets/232c1777-76ee-4c64-b0cf-5659be591151)

The implant can be seen in the 'Network' and 'File System' telemetry as well. The hash of the exe can be checked on VirusTotal, but it comes out clean it is a newly generated payload.

![Screenshot 2024-09-05 154338](https://github.com/user-attachments/assets/7d64b022-2c74-4d63-8d55-296d50120a51)

## Simulating Adversaries and Creating Detection Rules
Use `procdump -n lsass.exe -s lsass.dmp` to dump lsass.exe process memory as a means of stealing credentials. Since lsass.exe dumping is a known sensitive process, the EDR telemetry should generate events for this action.

![Screenshot 2024-09-05 155711](https://github.com/user-attachments/assets/decb2d27-2fee-46cf-8154-39c5e03ce899)

Now we can create a detection & response (D&R) rule to perform actions when this activity takes place. The created rule can be tested with the target event to see if the rule would match the event.

![Screenshot 2024-09-05 155957](https://github.com/user-attachments/assets/6b8c9bf5-239f-497d-8c6e-52457068e089)
![Screenshot 2024-09-05 160025](https://github.com/user-attachments/assets/7531f2cd-745d-4d77-9d25-70499c263273)

Running the same procdump command on the attacker machine we can observe new detections in LimaCharlie that matched the threat with the created detection signature.

![Screenshot 2024-09-05 162151](https://github.com/user-attachments/assets/26f1c86d-f90e-44ff-9729-d040848dc0a7)

## Simulating Adversaries and Creating Response Rules
Use `shell` command to create a reverse shell on the victim from the sliver server. Then run the command `vssadmin delete shadows /all` to delete volume shadow copies which is done by adversaries to prevent restoration of files to a previous state, for example, during a ransomware attack.

![Screenshot 2024-09-05 175822](https://github.com/user-attachments/assets/9b924ab9-08f0-4449-9530-0f506e7f80a1)

Check LimaCharlie for any default rule detections.

![Screenshot 2024-09-05 175943](https://github.com/user-attachments/assets/26a8ba3d-5cfd-4394-ba5e-6a3495c7b9d6)

Now we can create a Response rule to kill the parent process responsible for the command if the detection rule is matched.

![Screenshot 2024-09-05 180050](https://github.com/user-attachments/assets/70220319-4695-4099-99d8-71aebb4a5643)

Trying to run the same `vssadmin delete shadows /all` command again will trigger the response rule and will terminate the shell which is the parent process.

![Screenshot 2024-09-05 180204](https://github.com/user-attachments/assets/4e854265-f7ee-4b5a-b808-acc8863da30c)

## YARA Scanning 
We can configure LC to detect file system and process activities using YARA rules. Add a new YARA rule from the UK NCSC Advisory [here](https://www.ncsc.gov.uk/files/Advisory-further-TTPs-associated-with-SVR-cyber-actors.pdf)

![Screenshot 2024-09-05 183153](https://github.com/user-attachments/assets/d2049c50-c255-4f73-b0ee-cabeeb3ebddf)

Access the Sensor Console to manually run sensor commands against the endpoint. Run the command `yara_scan hive://yara/sliver -f C:\Users\User\Downloads\[payload_name].exe` and we can now observe detections.

![Screenshot 2024-09-05 183537](https://github.com/user-attachments/assets/50e448db-bc5d-4d9e-858b-37875273202f)
![Screenshot 2024-09-05 183614](https://github.com/user-attachments/assets/59604928-785c-4598-ae02-6e0887c7c880)


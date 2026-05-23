#!/home/bugbount/virtualenv/app/3.11/bin/python3
import subprocess

pip_path = '/home/bugbount/virtualenv/app/3.11/bin/pip'
requirements = '/home/bugbount/app/requirements.txt'

print(f"Installing from {requirements}...")
result = subprocess.run([pip_path, 'install', '-r', requirements],
                        capture_output=True, text=True)
print(result.stdout)
if result.stderr:
    print(result.stderr)
print("Done!")

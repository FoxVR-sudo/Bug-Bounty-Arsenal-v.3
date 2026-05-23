#!/home/bugbount/virtualenv/app/3.11/bin/python3.11_bin
import subprocess
import os

os.chdir('/home/bugbount/app')
python_path = '/home/bugbount/virtualenv/app/3.11/bin/python3.11_bin'

print("Running migrations...")
result = subprocess.run([python_path, 'manage.py', 'migrate'],
                        capture_output=True, text=True)
print(result.stdout)
if result.stderr:
    print(result.stderr)

print("\nCollecting static files...")
result = subprocess.run([python_path, 'manage.py', 'collectstatic', '--noinput'],
                        capture_output=True, text=True)
print(result.stdout)
if result.stderr:
    print(result.stderr)

print("\nDone!")

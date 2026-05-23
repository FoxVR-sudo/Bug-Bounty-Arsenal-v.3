import subprocess
import os

os.chdir('/home/bugbount/app')

# Set environment to use virtualenv
env = os.environ.copy()
env['PATH'] = '/home/bugbount/virtualenv/app/3.11/bin:' + env['PATH']

print("Running migrations...")
result = subprocess.run(['python', 'manage.py', 'migrate'],
                        capture_output=True, text=True, env=env)
print(result.stdout)
if result.stderr:
    print("STDERR:", result.stderr)

print("\nCollecting static files...")
result = subprocess.run(['python', 'manage.py', 'collectstatic', '--noinput'],
                        capture_output=True, text=True, env=env)
print(result.stdout)
if result.stderr:
    print("STDERR:", result.stderr)

print("\nDone!")

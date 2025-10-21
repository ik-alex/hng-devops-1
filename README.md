This is my Task 1 on HNG Internship

## The Task Description

Task Objective
Develop a robust, production-grade Bash script that automates the setup, deployment, and configuration of a Dockerized application on a remote Linux server.
:hammer_and_wrench: Task Breakdown
Your script (deploy.sh) should be a single, executable Bash file that performs all actions in sequence, with proper error handling, validation, and logging throughout.

1. Collect Parameters from User Input
   Prompt for and validate:
   Git Repository URL
   Personal Access Token (PAT)
   Branch name (optional; defaults to main)
   Remote server SSH details:
   Username
   Server IP address
   SSH key path
   Application port (internal container port)
2. Clone the Repository
   Authenticate and clone the repo using the PAT.
   If it already exists, pull the latest changes instead.
   Switch to the specified branch.

3. Navigate into the Cloned Directory
   Automatically cd into the cloned project folder.
   Verify that a Dockerfile or docker-compose.yml exists.
   Log success or failure.

4. SSH into the Remote Server
   Establish SSH connection with provided credentials.
   Perform connectivity checks (ping or SSH dry-run).
   Execute remaining commands remotely (ssh user@ip "commands...").

5. Prepare the Remote Environment
   On the remote host:
   Update system packages.
   Install Docker, Docker Compose, and Nginx (if missing).
   Add user to Docker group (if needed).
   Enable and start services.
   Confirm installation versions.

6. Deploy the Dockerized Application
   Transfer project files (via scp or rsync).
   Navigate to project directory.
   Build and run containers (docker build + docker run or docker-compose up -d).
   Validate container health and logs.
   Confirm app accessibility on the specified port.

7. Configure Nginx as a Reverse Proxy
   Dynamically create or overwrite Nginx config.
   Forward HTTP (port 80) traffic to container’s internal port.
   Ensure SSL readiness (optional self-signed cert or Certbot placeholder).
   Test config and reload Nginx.

8. Validate Deployment
   Confirm that:
   Docker service is running.
   The target container is active and healthy.
   Nginx is proxying correctly.
   Test endpoint using curl or wget locally and remotely.

9. Implement Logging and Error Handling
   Log all actions (success/failure) to a timestamped log file (e.g., deploy_YYYYMMDD.log).
   Include trap functions for unexpected errors.
   Use meaningful exit codes per stage.

10. Ensure Idempotency and Cleanup
    Script should safely re-run without breaking existing setups.
    Gracefully stop/remove old containers before redeployment.
    Prevent duplicate Docker networks or Nginx configs.
    (Optional) Include a --cleanup flag to remove all deployed resources.
    :package: Submission Guidelines
    Push your Bash script (deploy.sh) and a clear README.md to your GitHub repo.
    Script must be POSIX-compliant and executable (chmod +x deploy.sh).
    Do not use configuration management tools like Ansible or Terraform.
    :pushpin: Submission Process
    Verify your server works (test from multiple networks if possible)
    Go to the #track-devops and stage-1-devops channel in Slack
    Run the command: “/stage-one-devops”
    Submit:
    Your fullname and
    Your github repo url in this format https://github.com/username/repo
11. Please check Thanos bot to see the error message or success message after each attempt.
    :alarm_clock: Deadline & Attempts
    Deadline: 11:59 PM GMT, 22nd October 2025
    Attempts Allowed: 5
    Late Submissions: :x: Not accepted
    :gear: This task simulates real DevOps work. Employers at HNG are looking for interns who can deploy, document, and deliver. You got this, cool Keeds! :sunglasses: @channel

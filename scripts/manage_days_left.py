#!/usr/bin/env python3

# this script will run as a cron_job at 12pm midnight, London Time | (GMT+1)

# query db for all user's config data excluding the one's who don't have a config_file name (None) and day's paid for is 0.
# for user's with config_file name and days_paid is 0, config_file becomes deleted (None).
# for user's with config_file name and days_paid is not 0 (i.e. days_paid > 0), days_paid -= 1, we'll deduct one day out of it
# (a last final check) re-check user's with config_file name and days_paid is 0 (after the substraction), config_file becomes deleted (None).
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


import pytz
import httpx
from httpx import Timeout
from datetime import datetime
from sqlalchemy.orm import Session
from QUIET.models import user_configs  # user_configs model is defined here
from database import engine  # Importing database engine

def manage_user_configs():
    try:
        # Create a new database session
        with Session(engine) as session:
            # Query users who have a config_file and days_paid > 0
            users = session.query(user_configs).filter(
                user_config.config.isnot(None)
            ).all()

            for user in users:
                if user.days_paid > 0:
                    # Deduct one day from days_paid
                    user.days_paid -= 1

                # After deduction, if days_paid is 0, delete the record
                if user.days_paid == 0:
                    # Get the config file and server IP (assuming you have server_ip stored or fetched)
                    config_file = user.config
                    server_ip = user.server_ip  # assuming you have this data

                    try:
                        with httpx.Client(timeout=Timeout(50.0)) as client:
                            # set timeout to 50 seconds
                            response = client.get("http://{server_ip}/revoke_peer/{config_file}/".format(server_ip=server_ip, config_file=config_file), headers={"Content-Type": "application/json"})
                    except httpx.TimeoutException as e:
                        print("An error occurred while requesting")
                        raise HTTPException(status_code=500, detail=str(e))
                    except Exception as e:
                        print("Failed to revoke config file")
                        raise HTTPException(status_code=500, detail=str(e))

                    if response.status_code == 200:
                        session.delete(user)
                    else:
                        # Handle failed request (e.g., log it or raise an error)
                        print(f"Failed to revoke config file {config_file} on server {server_ip}")
    
            # Commit the changes to the database
            session.commit()
    except Exception as e:
        print(str(e))


if __name__ == "__main__":
    # Set timezone for London (GMT+1)
    # london_time = pytz.timezone('Europe/London')
    # current_time = datetime.now(london_time)
    
    #print(f"Script started at: {current_time}")
    print("script started!\n")
    
    # Call the function to update user configs
    manage_user_configs()
    print("User configs updated successfully!")

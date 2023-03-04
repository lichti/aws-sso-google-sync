#!/usr/bin/env python
# coding: utf-8

# # Script to provision Google Directory users and groups in AWS IAM Identity Center (Old AWS SSO) using SCIM

# * Author: Gustavo Lichti Mendonça
# * Mail: [gustavo.lichti@gmail.com](mailto:gustavo.lichti@gmail.com)
# * This Code: [https://github.com/lichti/aws-sso-google-sync
# ](https://github.com/lichti/aws-sso-google-sync
# )

# ## Why i need todo this

# Why Google Directory and SAML integration do not have SCIM integration

# ## Dependencies installing

# In[ ]:


get_ipython().run_cell_magic('bash', '', 'pip install requests\npip install pyyaml\npip install google-api-python-client\npip install oauth2client\npip install google-auth-httplib2\npip install google-auth-oauthlib\n')


# ## Imports

# In[ ]:


import requests
import json
import configparser
import logging
import httplib2

from apiclient.discovery import build
from google.oauth2 import service_account


# ## Logs
# 
# [https://googleapis.github.io/google-api-python-client/docs/logging.html](https://googleapis.github.io/google-api-python-client/docs/logging.html)

# In[ ]:


logger = logging.getLogger()
logger.setLevel(logging.INFO)
httplib2.debuglevel = 0


# ## Load config file with credentials

# Read more about configparser: [https://docs.python.org/3/library/configparser.html](https://docs.python.org/3/library/configparser.html)
# 
# Config Teamplate:
# 
# ```text
# [AWS-SSO-SCIM]
# base_url = https://scim.us-east-1.amazonaws.com/YOUR-AWS-SSO-ID/scim/v2/
# bearertoken = YOUR-AWS-SSO-BEARERTOKEN
# deleted_group_action=empty
# 
# [GOOGLE-ADMIN]
# domain = xyz.com.br
# groups_filter = name:AWS-SSO*
# credentials_file=aws-sso-google-sync.json
# ```
# 
# - ```deleted_group_action``` defines the action for when a group is removed in Google Directory and can be:
#   - ```empty```: To remove all users from the group on the AWS side, but not delete it.
#   - ```remove```: To delete the group on the AWS side
# - ```group_filter``` use search for groups rules.
#   - See more: [https://developers.google.com/admin-sdk/directory/v1/guides/search-groups](https://developers.google.com/admin-sdk/directory/v1/guides/search-groups)

# In[ ]:


config = configparser.ConfigParser()
config.read('aws-sso-scim-google-sync.ini')


# ### SCIM AWS SSO CONFIG

# Learn more about AWS SSO SCIM:
# * [https://docs.aws.amazon.com/singlesignon/latest/developerguide/supported-apis.html](https://docs.aws.amazon.com/singlesignon/latest/developerguide/supported-apis.html)

# In[ ]:


base_url = config['AWS-SSO-SCIM']['base_url']
bearertoken = config['AWS-SSO-SCIM']['bearertoken']
deleted_group_action = config['AWS-SSO-SCIM']['deleted_group_action']
users_url = f"{base_url}Users"
headers_auth = {"Authorization": f"Bearer {bearertoken}", "Content-type": "application/json"}


# ### GOOGLE ADMIN CONFIG

# In[ ]:


google_domain = config['GOOGLE-ADMIN']['domain']
groups_filter = config['GOOGLE-ADMIN']['groups_filter']
google_credentials_file = config['GOOGLE-ADMIN']['credentials_file']


# ## HTTP helpers

# Basic http methods helpers (get, post, put, patch, delete)
# 
# Recommended reading: 
# * [https://datatracker.ietf.org/doc/html/rfc7231#section-4.3](https://datatracker.ietf.org/doc/html/rfc7231#section-4.3)
# * [https://datatracker.ietf.org/doc/html/rfc7644#section-3.2](https://datatracker.ietf.org/doc/html/rfc7644#section-3.2)

# ### Get

# In[ ]:


def get(path=None, params=None):
    return requests.get(f"{base_url}{path}",headers=headers_auth, params=params)


# ### Post

# In[ ]:


def post(path=None, params=None, data=None):
    return requests.post(f"{base_url}{path}",headers=headers_auth, data=data)


# ### Put

# In[ ]:


def put(path=None, params=None, data=None):
    return requests.put(f"{base_url}{path}",headers=headers_auth, data=data)


# ### Patch

# In[ ]:


def patch(path=None, params=None, data=None):
    return requests.patch(f"{base_url}{path}",headers=headers_auth, data=data)


# ### Delete

# In[ ]:


def delete(path=None):
    return requests.delete(f"{base_url}{path}",headers=headers_auth)


# ## SCIM helpers

# Basic SCIM methods helpers
# 
# Learn more abut SCIM:
# * [https://datatracker.ietf.org/doc/html/rfc7642](https://datatracker.ietf.org/doc/html/rfc7642)
# * [https://datatracker.ietf.org/doc/html/rfc7643](https://datatracker.ietf.org/doc/html/rfc7643)
# * [https://datatracker.ietf.org/doc/html/rfc7644](https://datatracker.ietf.org/doc/html/rfc7644)
# * [https://openid.net/specs/fastfed-scim-1_0-02.html#rfc.section.4](https://openid.net/specs/fastfed-scim-1_0-02.html#rfc.section.4)

# ### Users

# #### CreateUser
# 
# - [https://datatracker.ietf.org/doc/html/rfc7644#section-3.3](https://datatracker.ietf.org/doc/html/rfc7644#section-3.3)

# In[ ]:


def createUser(userName=None,familyName=None,givenName=None,displayName=None,email=None,
               preferredLanguage="en-US",locale="en-US",timezone="America/Sao_Paulo",active=True):
    if userName and familyName and givenName and displayName and email:
        data = {
            "userName": f"{userName}",
            "name": {
                "familyName": f"{familyName}",
                "givenName": f"{givenName}",
            },
            "displayName": f"{displayName}",
            "emails": [
                {
                    "value": f"{email}",
                    "type": "work",
                    "primary": True
                }
            ],
            "preferredLanguage": f"{preferredLanguage}",
            "locale": f"{locale}",
            "timezone": f"{timezone}",
            "active": f"{active}",
        }
        res = post(path=f"Users", data=json.dumps(data))
        if res.status_code == 201:
            return json.loads(res.text)['id']
        else:
            logging.info(res.content)


# #### ListUsers
# 
# - [https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.1](https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.1)

# In[ ]:


def listUsers(params=None):
    res = get(path='Users',params=params)
    if res.status_code == 200:
        users = json.loads(res.text)
        return users


# #### HasUserByUsername
# 
# - [https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.1](https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.1)

# In[ ]:


def hasUserByUsername(userName=None):
    if userName:
        users = listUsers(f'filter=userName eq "{userName}"')['Resources']
        for u in users:
            if u['userName'] == userName:
                return True
    return False


# #### GetUserIDByUsername
# 
# - [https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.1](https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.1)

# In[ ]:


def getUserIDByUsername(userName=None):
    if userName:
        users = listUsers(f'filter=userName eq "{userName}"')['Resources']
        for u in users:
            if u['userName'] == userName:
                return u['id']


# #### GetUser
# 
# - [https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.1](https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.1)

# In[ ]:


def getUser(user_id=None):
    if user_id:
        res = get(path=f"Users/{user_id}")
        if res.status_code == 200:
            return json.loads(res.text)


# #### ReplaceUser
# 
# - [https://datatracker.ietf.org/doc/html/rfc7644#section-3.5.1](https://datatracker.ietf.org/doc/html/rfc7644#section-3.5.1)

# In[ ]:


def replaceUser(user_id=None,userName=None,familyName=None,givenName=None,displayName=None,email=None,
               preferredLanguage="en-US",locale="en-US",timezone="America/Sao_Paulo",active=True):
    if user_id and userName and familyName and givenName and displayName and email:
        data = {
            "id": f"{user_id}",
            "userName": f"{userName}",
            "name": {
                "familyName": f"{familyName}",
                "givenName": f"{givenName}",
            },
            "displayName": f"{displayName}",
            "emails": [
                {
                    "value": f"{email}",
                    "type": "work",
                    "primary": True
                }
            ],
            "preferredLanguage": f"{preferredLanguage}",
            "locale": f"{locale}",
            "timezone": f"{timezone}",
            "active": f"{active}",
        }
        res = put(path=f"Users/{user_id}", data=json.dumps(data))
        if res.status_code == 200:
            return json.loads(res.text)['id']
        else:
            logging.info(res.content)


# #### UpdateUser - I need improve this...
# 
# - [https://datatracker.ietf.org/doc/html/rfc7644#section-3.5.2](https://datatracker.ietf.org/doc/html/rfc7644#section-3.5.2)

# In[ ]:


def updateUser(user_id=None, data=None):
    return json.loads(patch(path=f"Users/{user_id}", data=data).text)


# #### DeleteUser
# 
# - [https://datatracker.ietf.org/doc/html/rfc7644#section-3.6](https://datatracker.ietf.org/doc/html/rfc7644#section-3.6)

# In[ ]:


def deleteUser(user_id=None):
    res = delete(path=f"Users/{user_id}")
    if res.status_code == 204:
        return True
    return False


# ### Groups

# #### CreateGroup
# 
# - [https://datatracker.ietf.org/doc/html/rfc7644#section-3.3](https://datatracker.ietf.org/doc/html/rfc7644#section-3.3)

# In[ ]:


def createGroup(groupName=None):
    if groupName:
        data = {"displayName": f"{groupName}"}
        res = post(path=f"Groups", data=json.dumps(data))
        if res.status_code == 201:
            return json.loads(res.text)['id']
        else:
            logging.info(res.content)


# #### ListGroups
# 
# - [https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.1](https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.1)

# In[ ]:


def listGroups(params=None):
    res = get(path='Groups',params=params)
    if res.status_code == 200:
        groups = json.loads(res.text)
        return groups


# #### HasGroupByName
# 
# - [https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.1](https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.1)

# In[ ]:


def hasGroupByName(groupName=None):
    if groupName:
        groups = listGroups(f'filter=displayName eq "{groupName}"')['Resources']
        for g in groups:
            if g['displayName'] == groupName:
                return True
    return False


# #### GetGroupIDByName
# 
# - [https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.1](https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.1)

# In[ ]:


def getGroupIBByName(groupName=None):
    if groupName:
        groups = listGroups(f'filter=displayName eq "{groupName}"')['Resources']
        for g in groups:
            if g['displayName'] == groupName:
                return g['id']


# #### GetGroup
# 
# - [https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.1](https://datatracker.ietf.org/doc/html/rfc7644#section-3.4.1)

# In[ ]:


def getGroup(group_id=None):
    if group_id:
        res = get(path=f"Groups/{group_id}")
        if res.status_code == 200:
            return json.loads(res.text)


# #### UpdateGroup
# 
# - [https://datatracker.ietf.org/doc/html/rfc7644#section-3.5.2](https://datatracker.ietf.org/doc/html/rfc7644#section-3.5.2)

# In[ ]:


def updateGroup(group_id=None, operation=None, members=[]):
    if len(members) > 0:
        data_values = [{"value": f"{member}"} for member in members]
    else:
        data_values = [{"value": ""}]
        
    if group_id and operation:
        logging.info(f"Updating {group_id}")
        data = {
            "schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations":[
                {
                    "op": f"{operation}",
                    "path": "members",
                    "value": data_values
                }
            ]
        }
        res = patch(path=f"Groups/{group_id}", data=json.dumps(data))
        if res.status_code == 204:
            return True
        else:
            logging.debug(res.content)
            return False


# #### DeleteGroup
# 
# - [https://datatracker.ietf.org/doc/html/rfc7644#section-3.6](https://datatracker.ietf.org/doc/html/rfc7644#section-3.6)

# In[ ]:


def deleteGroup(group_id=None):
    res = delete(path=f"Groups/{group_id}")
    if res.status_code == 204:
        return True
    return False


# ### CreateOrUpdateUser

# Method for creating or updating a user by SCIM provisioning

# In[ ]:


def CreateOrUpdateUser(member=None):
    logging.info(f"{member['name']['fullName']} => {not member['suspended']}")
    if not hasUserByUsername(member['primaryEmail']):
        logging.info(f"--> Creating user {member['primaryEmail']} -> {member['name']['fullName']}")
        ID = createUser(userName=member['primaryEmail'],
                        familyName=member['name']['familyName'],
                        givenName=member['name']['givenName'],
                        displayName=member['name']['fullName'],
                        email=member['primaryEmail'],
                        preferredLanguage="en-US",
                        locale="en-US",
                        timezone="America/Sao_Paulo",
                        active=not member['suspended'])
        if ID:
            logging.info(f"----> User created: {ID}")
        else:
            logging.info("----> User create failed")
    else:
        ID = getUserIDByUsername(member['primaryEmail'])
        logging.info(f"--> Updating user {member['primaryEmail']} -> {member['name']['fullName']} -> {ID}")  
        if replaceUser(user_id=ID,
                       userName=member['primaryEmail'],
                       familyName=member['name']['familyName'],
                       givenName=member['name']['givenName'],
                       displayName=member['name']['fullName'],
                       email=member['primaryEmail'],
                       preferredLanguage="en-US",
                       locale="en-US",
                       timezone="America/Sao_Paulo",
                       active=not member['suspended']):
            logging.info("----> User updated")
        else:
            logging.info("----> User update failed")
    return ID


# ## Google API Admin Directory Helpers
# 
# - [https://googleapis.github.io/google-api-python-client/docs/dyn/admin_directory_v1.html](https://googleapis.github.io/google-api-python-client/docs/dyn/admin_directory_v1.html)

# ### get_groups
# 
# - [https://googleapis.github.io/google-api-python-client/docs/pagination.html
# ](https://googleapis.github.io/google-api-python-client/docs/pagination.html
# )
# - [https://googleapis.github.io/google-api-python-client/docs/dyn/admin_directory_v1.groups.html](https://googleapis.github.io/google-api-python-client/docs/dyn/admin_directory_v1.groups.html)

# In[ ]:


def get_groups(domain=None, maxResults=50, query=None, auth=None):
    groups = []
    resource = auth.groups()
    request = resource.list(domain=domain,maxResults=maxResults, query=query)
 
    while request is not None:
        groups_results = request.execute()

        for group in groups_results.get('groups', []):
            del group['etag']
            groups.append(group)
            
        request = resource.list_next(request, groups_results)
        
    return groups


# ### get_group_members
# 
# - [https://googleapis.github.io/google-api-python-client/docs/pagination.html
# ](https://googleapis.github.io/google-api-python-client/docs/pagination.html
# )
# - [https://googleapis.github.io/google-api-python-client/docs/dyn/admin_directory_v1.members.html](https://googleapis.github.io/google-api-python-client/docs/dyn/admin_directory_v1.members.html)

# In[ ]:


def get_group_members(group_id, maxResults=50,auth=None):
    members = []
    resource = auth.members()
    request = resource.list(groupKey=group_id,maxResults=maxResults)
    
    while request is not None:
        members_results = request.execute()

        for member in members_results.get('members', []):
            if member['type'] == 'USER':
                del member['etag']
                members.append(member)

            if member['type'] == 'GROUP':
                for member in get_group_members(member['email'], auth=auth):
                    members.append(member)
        request = resource.list_next(request, members_results)
        
    #Remove duplicated users
    return [dict(member_t) for member_t in {tuple(member.items()) for member in members}]


# ### get_user
# 
# - [https://googleapis.github.io/google-api-python-client/docs/dyn/admin_directory_v1.users.html](https://googleapis.github.io/google-api-python-client/docs/dyn/admin_directory_v1.users.html)

# In[ ]:


def get_user(userKey, auth=None):
    user = auth.users().get(userKey=userKey).execute()
    del user['etag']
    return user


# ## Generic Helpers

# ### listOfUsernamesToIDS

# Helper to create a list of IDs from a list of usernames. Need a dictionary to do the black magic to work

# In[ ]:


def listOfUsernamesToIDS(usernames=None, usernames_dict=None):
    IDs=[]
    for username in usernames:
        if username in usernames_dict:
            IDs.append(usernames_dict[username])
    return IDs


# ## AWS SSO SCIM SYNC WITH GOOGLE DIRECTORY
# 
# ***It's time!***
# 
# - [https://googleapis.github.io/google-api-python-client/docs/](https://googleapis.github.io/google-api-python-client/docs/)
# - [https://googleapis.github.io/google-api-python-client/docs/epy/index.html](https://googleapis.github.io/google-api-python-client/docs/epy/index.html)
# 

# ### Configure Google Admin Authentication
# 
# - [https://googleapis.github.io/google-api-python-client/docs/oauth.html
# ](https://googleapis.github.io/google-api-python-client/docs/oauth.html
# )
# - [https://googleapis.github.io/google-api-python-client/docs/oauth-server.html](https://googleapis.github.io/google-api-python-client/docs/oauth-server.html)

# In[ ]:


target_scopes = ['https://www.googleapis.com/auth/admin.directory.user',
                'https://www.googleapis.com/auth/admin.directory.group',
                'https://www.googleapis.com/auth/admin.directory.group.member',
                'https://www.googleapis.com/auth/admin.directory.group.member.readonly',
                'https://www.googleapis.com/auth/admin.directory.group.readonly',
                'https://apps-apis.google.com/a/feeds/groups/',
                'https://www.googleapis.com/auth/admin.directory.user.readonly',
                'https://www.googleapis.com/auth/cloud-platform']

source_credentials = (
    service_account.Credentials.from_service_account_file(
        google_credentials_file,
        scopes=target_scopes))


# ### Google API Admin resource object
# 
# - [https://googleapis.github.io/google-api-python-client/docs/epy/googleapiclient.discovery-module.html#build](https://googleapis.github.io/google-api-python-client/docs/epy/googleapiclient.discovery-module.html#build)

# In[ ]:


google_srv_auth = build('admin', 'directory_v1', credentials=source_credentials)


# ### Local variables

# #### List groups_with_members  

# List to store all groups and their members (rich data)
# 
# ```
# [
#   {'group_name': '', 'group_email': '', 'group_members': {}}
# ]
# ```

# In[ ]:


groups_with_members = []


# #### List members_dict

# Dict to store username => id
# 
# ```{'username1': 'id1', 'username2': 'id2', 'username..n': 'id..n'}```

# In[ ]:


members_dict={}


# #### List members_unique

# List of members dict
# 
# ``` [{member1}, {member2}, {member..n}] ```

# In[ ]:


members_unique=[]


# ### Populate groups_with_members 

# In[ ]:


for group in get_groups(domain=google_domain, query=groups_filter, auth=google_srv_auth):
    group_members = [get_user(user['email'], auth=google_srv_auth) for user in get_group_members(group['email'], auth=google_srv_auth)]
    groups_with_members.append({'group_name': group['name'],
                                'group_email': group['email'],
                                'group_members': group_members})


# ### Populate members_dict and members_unique

# In[ ]:


total_processed=0
for group in groups_with_members:
    if group['group_members']:
        for member in group['group_members']:
            total_processed = total_processed+1
            if not member in members_unique:
                members_unique.append(member)
                members_dict[member['primaryEmail']] = getUserIDByUsername(member['primaryEmail'])
                
logging.info(f"Groups: {len(groups_with_members)} | Processed members: {total_processed} | Unique members: {len(members_unique)}")


# ### Remove or Empty deleted groups from Google Directory

# In[ ]:


google_groups=[ group['name'] for group in get_groups(domain=google_domain, query=groups_filter, auth=google_srv_auth)]
awssso_groups=[ group['displayName'] for group in listGroups()['Resources']]
removed_groups=list(set(awssso_groups)-set(google_groups))

for group in removed_groups:
    GroupID = getGroupIBByName(group)
    if deleted_group_action == 'empty':
        updateGroup(GroupID,"replace",[])
        
    if deleted_group_action == 'remove':
        if deleteGroup(GroupID):
            logging.info(f"Group deleted => {group}")


# ### Create or Update unique members

# In[ ]:


for n, member in enumerate(members_unique, 1):
    logging.info(f">{n}/{len(members_unique)}")
    CreateOrUpdateUser(member)


# ### Create or Update groups

# In[ ]:


for step, group in enumerate(groups_with_members, 1):
    group_name = group['group_name']
    logging.info(f"({step}/{len(groups_with_members)}) Working in the group: {group_name}")
    members=[]
    if group['group_members']:
        for member in group['group_members']:
            members.append(member['primaryEmail'])
    if hasGroupByName(group_name):
        logging.info(f"--> Group exists")
        IDs = listOfUsernamesToIDS(members,members_dict)
        GroupID = getGroupIBByName(group_name)
        logging.info(GroupID)
        logging.info(IDs)
        if updateGroup(GroupID,"replace",IDs):
            logging.info("----> Group members updated")
        else:
            logging.info("----> Group members update failed")
    else:
        logging.info(f"--> Creating group")
        GroupID = createGroup(group_name)
        if GroupID:
            logging.info("----> Group created")
            IDs = listOfUsernamesToIDS(members,members_dict)
            if updateGroup(GroupID,"replace",IDs):
                logging.info("------> Group members updated")
            else:
                logging.info("------> Group members update failed")
        else:
            logging.info("----> Group create failed")


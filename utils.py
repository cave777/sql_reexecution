import pdb

import snowflake.connector
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import hvac
import os
import logging
import glob
from zipfile import ZipFile
import requests
import json


def authtoken():
    url = "https://sf-api.cisco.com/api-token-auth/"
    data = {"username": "continuousdeployment", "password": "Cisco123!!"}
    r = requests.post(url=url, data=data)
    response = r.json()
    return response["token"]


def fetch_creds(username, sfaccount):
    auth_token = authtoken()
    headers = {"Authorization": "token " + auth_token + ""}
    url = "https://sf-api.cisco.com/snowflake/v1/operations/vault/token?svc_account=" + username + "&sf_account=" + sfaccount + ""
    r = requests.get(url=url, headers=headers)
    response = r.json()
    value = json.dumps(response["returnObject"])
    data = json.loads(value)
    vtoken = data['Token1']
    return vtoken


# ********************************************************
# Connect to snowflake database
# *********************************************************
def open_database_connection(config, username, account):
    # data = fetch_creds(config.config_properties.user, config.config_properties.account)
    data = fetch_creds(username, account)
    # Connect to Keeper to collect secrets
    client = hvac.Client(
        # url=config.config_properties.keeper_uri,
        # namespace=config.config_properties.keeper_namespace,
        # token=config.config_properties.keeper_token
        url=data['Keeper_url'],
        namespace=data['Keeper_namespace'],
        token=data['token']
    )
    # Secrets are stored within the key entitled 'data'
    # keeper_secrets = client.read(config.config_properties.secret_path)['data']
    keeper_secrets = client.read(data['secret_key_path'])['data']
    passphrase = keeper_secrets['SNOWSQL_PRIVATE_KEY_PASSPHRASE']
    private_key = keeper_secrets['private_key']

    # PEM key must be byte encoded
    key = bytes(private_key, 'utf-8')

    p_key = serialization.load_pem_private_key(
        key
        , password=passphrase.encode()
        , backend=default_backend()
    )

    pkb = p_key.private_bytes(
        encoding=serialization.Encoding.DER
        , format=serialization.PrivateFormat.PKCS8
        , encryption_algorithm=serialization.NoEncryption())

    conn = snowflake.connector.connect(
        # user=config.config_properties.user
        # , account=config.config_properties.account
        user=username
        , account=account
        , warehouse=config.config_properties.warehouse
        , role=config.config_properties.role
        # , database=config.config_properties.database
        # , schema=config.config_properties.schema
        # , timezone=config.config_properties.timezone
        # , password=config.config_properties.password
        , private_key=pkb
    )
    return conn


# ********************************************************
# Read list of Sql Commands and executes them sequentually
# starting at start point defined in start_point file
# If everything is successful then start point file is removed
# Otherwise starting point is modified
# *********************************************************
def execute_sqls(cs, sqlCommands, file_start, sql_start, start_point_name, path, log):
    pdb.set_trace()
    file = path + '/' + start_point_name + '.txt'
    for i in range(sql_start - 1, len(sqlCommands)):
        log.info("    Step %d" % (i + 1))
        log.info("    " + sqlCommands[i])

        try:
            cs.execute(sqlCommands[i])
            log.info("    %s query succeeded" % (sqlCommands[i]))
        except snowflake.connector.errors.ProgrammingError as e:
            with open(file, "w") as fd:
                fd.write("Start File From=%d\n" % (file_start))
                fd.write("Start Sql From=%d" % (i + 1))

            log.info("    %s query failed" % (sqlCommands[i]))
            # default error message
            log.info(e)
            # customer error message
            # log.info('Error {0} ({1}): {2} ({3})'.format(e.errno, e.sqlstate, e.msg, e.sfqid))

            return False

    return True


# ********************************************************
# Get starting point from start point file if exists
# Otherwise create start point file with starting point 1,1
# *********************************************************
def getStartPoint(filename):
    file = filename + '.txt'
    if not os.path.exists(file):
        with open(file, "w") as fd:
            fd.write("Start File From=1\n")
            fd.write("Start Sql From=1")

        start_point = (1, 1)
    else:
        with open(file, "r") as fd:
            checkPointFile = fd.read()

        start_point_list = checkPointFile.split("\n")
        start_point = int(start_point_list[0].split("=")[-1]), int(start_point_list[1].split("=")[-1])

    return start_point


# ********************************************************
# Rewrite sql statements from source to target
# taken from sql file
# *********************************************************
def getTargetSqls(file, sourceSql, targetSql, log):
    pdb.set_trace()
    dbs = []
    with open(file) as fd:
        sqlFile = fd.read()

    sqlCommands = sqlFile.split(';')
    # sqlCommands.pop()
    for i in range(len(sqlCommands)):
        if bool(sqlCommands[i]):
            sqlCommands[i] = sqlCommands[i].replace("\n", " ")
            sqlCommands[i] = sqlCommands[i].replace("(", " ( ")
            sqlCommands[i] = sqlCommands[i].replace(")", " ) ")
            sqlCommands[i] = sqlCommands[i].replace(",", " , ")
            sqlCommands[i] = sqlCommands[i].strip()
            sqlCommands[i] = sqlCommands[i].replace("  ", " ")

    for i in range(len(sqlCommands)):
        if bool(sqlCommands[i]):
            dbs.append(set([]))
            log.info("    Before")
            log.info("    " + sqlCommands[i])
            stList = sqlCommands[i].split()
            if stList[0].startswith("--") and stList[0].endswith("--"):
                stList[0] += "\n"
            for j in range(len(stList)):
                st = stList[j].split(".")
                if len(st) == 3:
                    log.info("    " + str(st))
                    if sourceSql == "PRD":
                        if targetSql != "PRD":
                            stList[j] = stList[j].replace("_DB.", "_DB_" + targetSql + ".")
                    else:
                        if targetSql == "PRD":
                            stList[j] = stList[j].replace("_" + sourceSql + ".", ".")
                        else:
                            stList[j] = stList[j].replace("_" + sourceSql + ".", "_" + targetSql + ".")

            sqlCommands[i] = " ".join(stList) + ";"
            log.info("    After:")
            log.info("    " + sqlCommands[i])

    return sqlCommands


def extract_file_name(file_name):
    fn_list = file_name.split("/")
    name = fn_list[-1].split(".")
    return name[0]


def file_to_list(file_name):
    source_file = "%s" % (file_name)
    lines = open(source_file).read().splitlines()
    return lines


def list_to_file(file_name, sqls, target_dir):
    target_file = "%s/%s" % (target_dir, file_name)
    with open(target_file, 'w') as f:
        f.write("\n".join(sqls))


def transfer_files(source_dir, target_dir, source_file, target_file):
    files = glob.glob(source_dir + '/' + source_file)
    with ZipFile(target_dir + '/' + target_file, "w") as newzip:
        for file in files:
            newzip.write(file)


def getDatabases(cs, targetSql):
    sql = "show databases like '_%s';" % (targetSql)
    cs.execute(sql)
    databases = set([])
    for result in cs.fetchall():
        databases.add(result[1])

    return databases


def setup_logger(logger_name, log_file, level=logging.INFO):
    log_setup = logging.getLogger(logger_name)
    formatter = logging.Formatter('%(levelname)s: %(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
    fileHandler = logging.FileHandler(log_file, mode='a')
    fileHandler.setFormatter(formatter)
    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)
    log_setup.setLevel(level)
    log_setup.addHandler(fileHandler)
    log_setup.addHandler(streamHandler)

import argparse
import pdb

from ConfigObject import ConfigObject
import sys
import os
import logging
from utils import open_database_connection, execute_sqls, getTargetSqls, getStartPoint
from utils import file_to_list, extract_file_name, setup_logger


# def check_arg(args=None):
#     parser = argparse.ArgumentParser(description='Script to learn basic argparse')
#     parser.add_argument('-f', '--manifest_file',
#                         help='manifest_file',
#                         default='release.manifest')
#     parser.add_argument('-s', '--sourceSql',
#                         help='sourceSql',
#                         default='PRD')
#     parser.add_argument('-t', '--targetSql',
#                         help='targetSql',
#                         required=True)
#     parser.add_argument('-v', '--version',
#                         help='version',
#                         required=True)
#     parser.add_argument('-a', '--appName',
#                         help='appName',
#                         required=True)
#
#     results = parser.parse_args(args)
#     return results.manifest_file, results.sourceSql, results.targetSql, results.version, results.appName


def main():
    # manifest_file, sourceSql, targetSql, version, appName = check_arg(sys.argv[1:])
    # ini_file = "%s/config/%s.ini" % (os.environ['HOME'], os.environ['APP_NAME'])
    accounts = {"DV": "CISCODEV.US-EAST-1", "TS": "CISCOSTAGE.US-EAST-1", "PR": "CISCO.US-EAST-1"}
    # ini_file = "%s/config/%s.ini" % (os.environ['HOME'], appName)
    # config = ConfigObject(filename=ini_file)
    # ctx = open_database_connection(config, appName, accounts[targetSql[:2]])
    # cs = ctx.cursor()
    #
    # targetPath = targetSql
    # if targetSql == 'PRD':
    #     targetPath = 'PROD'
    #
    # path = "%s/%s/%s/sql/%s" % (os.environ['HOME'],
    #                             targetPath,
    #                             appName,
    #                             version)
    #
    # log_file_path = "%s/%s/%s/log/%s" % (os.environ['HOME'],
    #                                      targetPath,
    #                                      appName,
    #                                      version)

    # if not os.path.exists(log_file_path):
    #     os.mkdir(log_file_path)

    try:
        sqlFiles = file_to_list('release.manifest')
        fileName = extract_file_name('release.manifest')
        start_point_name = "start_point_" + fileName
        start_point_file = start_point_name + ".txt"
        file_start, sql_start = getStartPoint(start_point_name)
        done = True
        for i in range(file_start - 1, len(sqlFiles)):
            sqlFileName = extract_file_name(sqlFiles[i])
            log_file = sqlFileName + ".log"
            setup_logger(sqlFileName, log_file)
            log = logging.getLogger(sqlFileName)
            log.info("SQL Execution Starts")

            sqlCommands = getTargetSqls(sqlFiles[i], 'PRD', 'DV3', log)
            pdb.set_trace()
            log.info(str(i + 1) + ".File " + sqlFiles[i] + ":")
            success = execute_sqls(cs, sqlCommands, i + 1, sql_start, start_point_name, path, log)
            if not success:
                done = False
                break

            log.info("SQL Execution Ends")

        if done:
            os.remove(start_point_file)
    finally:
        cs.close()
    ctx.close()


if __name__ == '__main__':
    main()

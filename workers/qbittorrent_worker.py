#!/usr/bin/env python
# encoding: utf-8
"""
下载检测
"""

import hashlib
import os
import time
import datetime
import traceback
import sys
import json
import socket
import threading
from hashlib import sha1
from random import randint
from struct import unpack
from socket import inet_ntoa
from threading import Timer, Thread
from time import sleep

reload(sys)
sys.setdefaultencoding("utf8")

sys.path.append('/usr/local/lib/python2.7/site-packages')




def formatTime():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def getRunDir():
    return os.getcwd()


def getRootDir():
    return os.path.dirname(os.path.dirname(getRunDir()))

# import pygeoip
import MySQLdb as mdb

from configparser import ConfigParser
cp = ConfigParser()
cp.read("../qb.conf")
section_db = cp.sections()[0]
DB_HOST = cp.get(section_db, "DB_HOST")
DB_USER = cp.get(section_db, "DB_USER")
DB_PORT = cp.getint(section_db, "DB_PORT")
DB_PASS = cp.get(section_db, "DB_PASS")
DB_NAME = cp.get(section_db, "DB_NAME")


section_qb = cp.sections()[1]
QB_HOST = cp.get(section_qb, "QB_HOST")
QB_PORT = cp.get(section_qb, "QB_PORT")
QB_USER = cp.get(section_qb, "QB_USER")
QB_PWD = cp.get(section_qb, "QB_PWD")

section_file = cp.sections()[2]
FILE_TO = cp.get(section_file, "FILE_TO")
FILE_TRANSFER_TO = cp.get(section_file, "FILE_TRANSFER_TO")
FILE_OWN = cp.get(section_file, "FILE_OWN")
FILE_GROUP = cp.get(section_file, "FILE_GROUP")
FILE_ENC_SWITCH = cp.get(section_file, "FILE_ENC_SWITCH")
FILE_API_URL = cp.get(section_file, "FILE_API_URL")
FILE_ASYNC_SWITCH = cp.get(section_file, "FILE_ASYNC_SWITCH")



section_task = cp.sections()[3]
TASK_RATE = cp.getint(section_task, "TASK_RATE")
TASK_COMPLETED_RATE = cp.getint(section_task, "TASK_COMPLETED_RATE")
TASK_DEBUG = cp.getint(section_task, "TASK_DEBUG")

rooDir = getRootDir()
ffmpeg_cmd = rooDir + "/lib/ffmpeg/ffmpeg"
if not os.path.exists(ffmpeg_cmd):
    ffmpeg_cmd = rooDir + "/lib/ffmpeg/bin/ffmpeg"


class downloadBT(Thread):

    def __init__(self):
        Thread.__init__(self)
        self.setDaemon(True)
        self.dbconn = mdb.connect(
            DB_HOST, DB_USER, DB_PASS, DB_NAME, port=DB_PORT, charset='utf8')
        self.dbconn.autocommit(False)
        self.dbcurr = self.dbconn.cursor()
        self.dbcurr.execute('SET NAMES utf8')
        self.qb = self.qb()

        _has_suffix = ['mp4', 'rmvb', 'flv', 'avi', 'mpg', 'mkv', 'wmv', 'avi']
        has_suffix = []
        for x in range(len(_has_suffix)):
            has_suffix.append('.' + _has_suffix[x])
            has_suffix.append('.' + _has_suffix[x].upper())
        self.has_suffix = has_suffix

    def query(self, sql):
        self.dbcurr.execute(sql)
        result = self.dbcurr.fetchall()
        data = map(list, result)
        return data

    def qb(self):
        from qbittorrent import Client
        url = 'http://' + QB_HOST + ':' + QB_PORT + '/'
        qb = Client(url)
        qb.login(QB_USER, QB_PWD)
        return qb

    def execShell(self, cmdstring, cwd=None, timeout=None, shell=True):
        import subprocess
        if shell:
            cmdstring_list = cmdstring
        else:
            cmdstring_list = shlex.split(cmdstring)
        if timeout:
            end_time = datetime.datetime.now() + datetime.timedelta(seconds=timeout)

        sub = subprocess.Popen(cmdstring_list, cwd=cwd, stdin=subprocess.PIPE,
                               shell=shell, bufsize=4096, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        while sub.poll() is None:
            time.sleep(0.1)
            if timeout:
                if end_time <= datetime.datetime.now():
                    raise Exception("Timeout：%s" % cmdstring)

        return sub.communicate()

    def md5(self, str):
        # 生成MD5
        try:
            m = hashlib.md5()
            m.update(str)
            return m.hexdigest()
        except:
            return False

    def readFile(self, filename):
        # 读文件内容
        try:
            fp = open(filename, 'r')
            fBody = fp.read()
            fp.close()
            return fBody
        except:
            return False

    def get_transfer_ts_file(self, to):
        return FILE_TRANSFER_TO + '/' + to + '.ts'

    def get_transfer_mp4_file(self, to):
        return FILE_TRANSFER_TO + '/' + to + '.mp4'

    def get_lock_file(self, to):
        return FILE_TRANSFER_TO + '/' + to + '.lock'

    def get_transfer_m3u5_dir(self, dirname, fname):
        return FILE_TO + '/m3u8/' + dirname + '/' + fname

    def fg_transfer_mp4_cmd(self, sfile, dfile):
        cmd = ffmpeg_cmd + ' -y -i "' + sfile + \
            '" -threads 1  -preset veryslow -crf 28 -c:v libx264 -strict -2 ' + dfile
        return cmd

    def fg_transfer_ts_cmd(self, file, to_file):
        cmd = ffmpeg_cmd + ' -y -i ' + file + \
            ' -s 480x360 -vcodec copy -acodec copy -vbsf h264_mp4toannexb ' + to_file
        return cmd

    def fg_m3u8_cmd(self, ts_file, m3u8_file, to_file):
        cmd = ffmpeg_cmd + ' -y -i ' + ts_file + ' -c copy -map 0 -f segment -segment_list ' + \
            m3u8_file + ' -segment_time 3 ' + to_file
        return cmd

    def fg_m3u8enc_cmd(self, ts_file, m3u8_file, to_file, enc_dir):
        cmd = ffmpeg_cmd + ' -y -i ' + ts_file + ' -threads 1 -strict -2 -hls_time 3 -hls_key_info_file ' + \
            enc_dir + '/enc.keyinfo.txt -hls_playlist_type vod -hls_segment_filename ' + to_file + ' '+ m3u8_file
        return cmd

    def debug(self, msg):
        return formatTime() + ":" + msg

    def lock(self, sign):
        l = self.get_lock_file(sign)
        self.execShell('touch ' + l)

    def unlock(self, sign):
        l = self.get_lock_file(sign)
        self.execShell('rm -rf ' + l)

    def islock(self, sign):
        l = self.get_lock_file(sign)
        if os.path.exists(l):
            return True
        return False

    def ffmpeg_file_sync(self):
        print 'file_sync... start'

        runDir = getRunDir()

        if FILE_ASYNC_SWITCH == '1':
            self.execShell('sh -x ' + runDir+'/rsync.sh')
        print 'file_sync... end'


    def ffmpeg(self, file=''):
        if not os.path.exists(FILE_TRANSFER_TO):
            self.execShell('mkdir -p ' + FILE_TRANSFER_TO)

        fname = os.path.basename(file)
        shash = self.sign_torrent['hash']
        md5file = self.md5(file)
        if not os.path.exists(file):
            print formatTime(), 'file not exists:', file
            return
        print self.debug('source file ' + file)


        mp4file = self.get_transfer_mp4_file(md5file)
        cmd_mp4 = self.fg_transfer_mp4_cmd(file, mp4file)
        if not os.path.exists(mp4file):
            print self.debug('cmd_mp4:' + cmd_mp4)
            os.system(cmd_mp4)
        else:
            print self.debug('mp4 exists:' + mp4file)

        if not os.path.exists(mp4file):
            print self.debug('mp4 not exists')
            return

        tsfile = self.get_transfer_ts_file(md5file)
        cmd_ts = self.fg_transfer_ts_cmd(mp4file, tsfile)
        if not os.path.exists(tsfile):
            print self.debug('cmd_ts:' + cmd_ts)
            os.system(cmd_ts)
        else:
            print self.debug('data_ts exists:' + mp4file)

        if not os.path.exists(tsfile):
            print self.debug('ts not exists')
            return

        md5Fname = self.md5(fname)
        m3u8_dir = self.get_transfer_m3u5_dir(shash, md5Fname)
        if not os.path.exists(m3u8_dir):
            self.execShell('mkdir -p ' + m3u8_dir)

        m3u8_file = m3u8_dir + '/index.m3u8'
        tofile = m3u8_dir + '/%010d.ts'
        print self.debug('tofile:' + tofile)
        # 加密m3u8
        if FILE_ENC_SWITCH != '0':
            enc_dir = '/tmp/qb_m3u8'
            cmd = self.fg_m3u8enc_cmd(tsfile, m3u8_file, tofile, enc_dir)
            if os.path.exists(m3u8_file):
                print self.debug('cmd_m3u8_enc exists:' + m3u8_file)
                print self.debug('cmd_m3u8_enc:' + cmd)
                self.ffmpeg_file_sync()
                return

            
            self.execShell('mkdir -p ' + enc_dir)
            self.execShell('openssl rand  -base64 16 > ' +
                           enc_dir + '/enc.key')
            self.execShell('rm -rf ' + enc_dir + '/enc.keyinfo.txt')

            fid = self.add_hash(fname, md5file)
            key = self.readFile(enc_dir + '/enc.key').strip()
            self.set_hashfile_key(fid, key)

            # FILE_API_URL
            url = FILE_API_URL.replace('{$KEY}', fid)
            enc_url = 'echo ' + url + ' >> ' + enc_dir + '/enc.keyinfo.txt'
            self.execShell(enc_url)
            enc_path = 'echo ' + enc_dir + '/enc.key >> ' + enc_dir + '/enc.keyinfo.txt'
            self.execShell(enc_path)
            enc_iv = 'openssl rand -hex 16 >> ' + enc_dir + '/enc.keyinfo.txt'
            self.execShell(enc_iv)
    
            os.system(cmd)
        else:

            if os.path.exists(m3u8_file):
                print self.debug('m3u8 exists:' + tofile)
                self.ffmpeg_file_sync()
                return

            cmd_m3u8 = self.fg_m3u8_cmd(tsfile, m3u8_file, tofile)
            print self.debug('cmd_m3u8:' + cmd_m3u8)
            os.system(cmd_m3u8)

            try:
                self.add_hash(fname, md5file)
            except Exception as e:
                print 'add_hash', str(e)

        self.execShell('chown -R ' + FILE_OWN + ':' +
                       FILE_GROUP + ' ' + m3u8_dir)

        self.ffmpeg_file_sync()

    def get_bt_size(self):
        total_size = '0'
        if 'size' in self.sign_torrent:
            total_size = str(self.sign_torrent['size'])

        if 'total_size' in self.sign_torrent:
            total_size = str(self.sign_torrent['total_size'])
        return total_size

    def get_hashlist_id(self):
        ct = formatTime()

        total_size = self.get_bt_size()

        shash = self.sign_torrent['hash']
        sname = self.sign_torrent['name']
        sname = mdb.escape_string(sname)

        info = self.query(
            "select id from pl_hash_list where info_hash='" + shash + "'")
        if len(info) > 0:
            pid = str(info[0][0])
        else:
            print 'insert into pl_hash_list data'
            pid = self.dbcurr.execute("insert into pl_hash_list (`name`,`info_hash`,`length`,`create_time`) values('" +
                                      sname + "','" + shash + "','" + total_size + "','" + ct + "')")
        return pid

    def get_hashfile_id(self, fname, m3u8_name, pid):
        ct = formatTime()

        info = self.query(
            "select id from pl_hash_file where name='" + fname + "' and pid='" + pid + "'")
        if len(info) == 0:
            print 'insert into pl_hash_file data !'
            fid = self.dbcurr.execute("insert into pl_hash_file (`pid`,`name`,`m3u8`,`create_time`) values('" +
                                      pid + "','" + fname + "','" + m3u8_name + "','" + ct + "')")
        else:
            print fname, ':', m3u8_name, 'already is exists!'
            fid = str(info[0][0])
        return fid

    def set_hashfile_key(self, fid, key):
        self.dbcurr.execute("update pl_hash_file set `key`='" +
                            mdb.escape_string(key) + "' where id=" + fid)

    def add_hash(self, fname, m3u8_name):
        print '-------------------------add_hash---start-----------------------'

        pid = self.get_hashlist_id()
        fid = self.get_hashfile_id(fname, m3u8_name, pid)

        print '-------------------------add_hash---end--------------------------'

        return fid

    def file_arr(self, path, filters=['.DS_Store']):
        file_list = []
        flist = os.listdir(path)

        for i in range(len(flist)):
            # 下载缓存文件过滤
            if flist[i] == '.unwanted':
                continue

            file_path = os.path.join(path, flist[i])
            if flist[i] in filters:
                continue
            if os.path.isdir(file_path):
                tmp = self.file_arr(file_path, filters)
                file_list.extend(tmp)
            else:
                file_list.append(file_path)
        return file_list

    def find_dir_video(self, path):
        flist = self.file_arr(path)
        video = []
        for i in range(len(flist)):
            t = os.path.splitext(flist[i])
            if t[1] in self.has_suffix:
                video.append(flist[i])
        return video

    def video_do(self, path):
        if os.path.isfile(path):
            t = os.path.splitext(path)
            if t[1] in self.has_suffix:
                self.ffmpeg(path)
        else:
            vlist = self.find_dir_video(path)
            for v in vlist:
                self.ffmpeg(v)

        return ''

    def checkTask(self):
        while True:
            torrents = self.qb.torrents(filter='downloading')
            tlen = len(torrents)
            if tlen > 0:
                print "downloading torrents count:", tlen
                for torrent in torrents:
                    print torrent['name'], ' task downloading!'
            else:
                print formatTime(), "no downloading task!"
            time.sleep(TASK_RATE)

    def completed(self):
        while True:

            torrents = self.qb.torrents(filter='completed')
            tlen = len(torrents)
            print "completed torrents count:", tlen
            if tlen > 0:
                for torrent in torrents:
                    self.sign_torrent = torrent
                    path = torrent['save_path'] + torrent['name']
                    path = path.encode()
                    try:
                        self.video_do(path)
                        if TASK_DEBUG == 0:
                            self.qb.delete_permanently(torrent['hash'])
                    except Exception as e:
                        print formatTime(), str(e)

                print formatTime(), "done task!"
            else:
                print formatTime(), "no completed task!"
            time.sleep(TASK_COMPLETED_RATE)


def test():
    while True:
        print formatTime(), "no download task!",
        time.sleep(1)
        test()

if __name__ == "__main__":

    dl = downloadBT()

    import threading
    task = threading.Thread(target=dl.checkTask)
    task.start()

    completed = threading.Thread(target=dl.completed)
    completed.start()

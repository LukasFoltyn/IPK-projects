import argparse
import re
import sys
import socket
import os

# returns data from server or error message
def GET_request_server(host_ip, port, file, server):

    TCP_client_socket = None
    try:
        TCP_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as err:
        print("Socket creation failed with error %s" % err, file=sys.stderr)

    GET_request = f'GET {file} FSP/1.0\r\nAgent: xfolty17\r\n Hostname: {server}\r\n\r\n'

    try:
        TCP_client_socket.connect((host_ip, port))
    except ConnectionRefusedError:
        print(f"Unable to connect '{server}' server.", file=sys.stderr)
        exit(1)

    try:
        TCP_client_socket.send(str.encode(GET_request))
    except:
        print('An problem occurred when sending data to the server.', file=sys.stderr)
        exit(1)
    # creating empty string encoded to bytes
    all_data = bytes()

    # looping while receiving data from server
    while True:
        try:
            recv_data = TCP_client_socket.recv(1024)
        except:
            print('An problem occurred when receiving data from the server.', file=sys.stderr)
            exit(1)
        else:
            if not recv_data:
                break
            all_data += recv_data

    # closing socket
    TCP_client_socket.close()

    return all_data

def check_answered_request(data_to_check, file_name):
    # taking just the first line for err check
    check_err = data_to_check.split(b'\r', 1)[0]

    # we were not able to find the specified file
    if check_err == b'FSP/1.0 Not Found':
        print(f"The specified file '{file_name}' was not found.", file=sys.stderr)
        return False

    # we sent a bad request to the server
    elif check_err == b'FSP/1.0 Bad Request':
        print('Bad request was sent to the server.', file=sys.stderr)
        exit(1)

    # something unexpected happened on the server
    elif check_err == b'FSP/1.0 Server Error':
        print('An error occurred on the server', file=sys.stderr)
        exit(1)
    return True

def create_file_in_dir(filename, direct, data_to_write):
    try:
        f_ptr = open(direct+'/'+filename, 'wb')
    except PermissionError:
        print(f"Permission error - unable to create '{filename}'", file=sys.stderr)
    else:
        f_ptr.write(data_to_write)
        f_ptr.close()

def create_directories(new_directories):
    path = './'
    for di in new_directories:
        path = os.path.join(path, di)
        if not os.path.exists(path):
            try:
                os.mkdir(path)
            except PermissionError:
                print(f"No permission to create '{path}' directory", file=sys.stderr)
    return path

# servers for creating directory hierarchy
# dir_to_make -> directories that needs to be created (nested)
# files that will be placed into the most nested folder
class Directory:
    def __init__(self, dirs, full_path_file, file_n):
        self.dir_to_make = dirs
        self.files_to_make = [[full_path_file, file_n]]

parser = argparse.ArgumentParser()

# adding script arguments
parser.add_argument('--server', '-n', nargs=1, help='NAMESERVER - IP address and port of named server.', type=str,
                    required=True)
parser.add_argument('--file', '-f', nargs=1, help='SURL - fsp protocol + server name +'
                                                  ' path to the file that is being downloaded.', type=str,
                    required=True)

# parsing command line arguments
args = parser.parse_args()

# converting command line arguments to strings
IPaddress_port = ''.join(args.server)
server_file = ''.join(args.file)

# checking correctly written protocol with server name and path to the file
# that user wants to download
# first group matches server name
# second group matches path to the file
# third group matches only the filename
server_path_check = re.fullmatch(r'^fsp://([\w.-]+)/([^/]*|.*/([^/]*))$', server_file)

# exiting if invalid data were given
if not server_path_check:
    print('Invalid SURL - ', server_file, file=sys.stderr)
    exit(1)

server_name = server_path_check.group(1)
file_to_get = server_path_check.group(2)

# third group only appears if the path is longer than just name itself
filename = server_path_check.group(3) if server_path_check.group(3) else file_to_get

# checking valid IP address and also the valid port
# first group matches IP (0-255.0-255.0-255.0-255)
# fifth group matches (port 1-65535)
address_port_check = re.fullmatch(r'''
                            ^(((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3} # first three parts of IP with dots
                            (25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])): # last part of IP with colon separating the port
                            ([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[1-4]\d{3}|65[1-5][1-3][1-5])$ # matching port
                                ''', IPaddress_port, re.VERBOSE)

# exiting if invalid data were given
if not address_port_check:
    print('Invalid IP address or port -', IPaddress_port, file=sys.stderr)
    exit(1)

IP = address_port_check.group(1)
PORT = int(address_port_check.group(5))

UDP_client_socket = None

try:
    UDP_client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except socket.error as err:
    print("Socket creation failed with error %s" % err, file=sys.stderr)

# if we are unable to get data from server in 2 seconds quit
UDP_client_socket.settimeout(2.0)
try:
    send_bytes = UDP_client_socket.sendto(str.encode(f'WHEREIS {server_name}'), (IP, PORT))
except PermissionError:
    print(f"No permission to send data to IP - {IP} and PORT - {PORT}", file=sys.stderr)
    exit(1)
else:
    if send_bytes == 0:
        print("Send operation through UDP failed.", file=sys.stderr)
        exit(1)

received_data = None
try:
    received_data = UDP_client_socket.recvfrom(512)
except socket.timeout:
    print(f"Unable to get data from IP - {IP} and PORT - {PORT}", file=sys.stderr)
    exit(1)

# received data is tuple, data we need are indexed with zero
# message format 'OK IP:PORT'
received_data = received_data[0].decode('UTF-8')

UDP_client_socket.close()

if received_data == 'ERR Not Found':
    print(f"No such server as '{server_name}' was found.", file=sys.stderr)
    exit(1)
elif received_data == 'ERR Syntax':
    print('Syntax error occurred.', file=sys.stderr)
    exit(1)

# removing 'OK ' part
received_data = received_data[3:]
# splitting the string into a IP and PORT
rec_IP, rec_PORT = received_data.split(':')
# convert PORT to int from str
rec_PORT = int(rec_PORT)


# get all files in directory --> special case
if filename == '*':
    # get list of all server files
    # by getting the content of 'index' file
    # that contains a list of all files on the server
    data = GET_request_server(rec_IP, rec_PORT, 'index', server_name)
    if not check_answered_request(data, 'index'):
        print('Unable to get all the files.', file=sys.stderr)

    # FSP/1.0 success Length:xx data we need
    # cut of the first part of the message we don't need
    all_server_files = data.decode('utf-8').split()[3:]

    # file_to_get includes path to the given file
    # if it's only *(no path specified), we want all files on server - no need to filter
    # but if it's not, we have to filter the files that are in specified path
    directory_to_skip = 0
    if file_to_get != '*':
        # get just the path without the * sign
        directory_to_copy = file_to_get[:-1]
        # filtering only the files that are in given path
        all_server_files = [x for x in all_server_files if re.match(rf"^{directory_to_copy}.*", x)]

        if not all_server_files:
            print(f"Given path '{directory_to_copy}' is not included in the index server file.")
            exit(1)

        # we don't want to create the full path in user's folder
        # so we skip all the directories leading to * sign
        directory_to_skip = len(directory_to_copy.split('/'))-1

    folder_hierarchy = {}

    for file in all_server_files:
        # splitting the path like a/b/c -> [a,b,c]
        # where a,b are directories to make and c is file
        dir_file_split = file.split('/')
        curr_filename = dir_file_split[-1]
        dirs_to_make = dir_file_split[directory_to_skip:-1]

        # if files have to be in created directories
        if dirs_to_make:

            # crating key for specific path
            key = re.sub(rf"/{curr_filename}$", '', file)

            if key in folder_hierarchy.keys():
                folder_hierarchy[key].files_to_make.append([file, curr_filename])
            else:
                folder_hierarchy[key] = Directory(dirs_to_make, file, curr_filename)

        # create file in current folder
        else:
            # split received data with status code into for blocks
            # the last one is just the data we need
            data = GET_request_server(rec_IP, rec_PORT, file, server_name)
            if check_answered_request(data, file):
                data = data.split(b'\n', 3)[3]
                create_file_in_dir(curr_filename, '.', data)

        # looping through objects typeof Directory
    # creating necessary directories for files
    for new_dir in folder_hierarchy.values():

        path_dir = create_directories(new_dir.dir_to_make)

        # looping through files that has to be placed
        # into just newly created directory
        # file[0] file with the path from the root folder
        # file[1] filename on its own
        for file in new_dir.files_to_make:
            data = GET_request_server(rec_IP, rec_PORT, file[0], server_name)
            if check_answered_request(data, file[0]):
                data = data.split(b'\n', 3)[3]
                create_file_in_dir(file[1], path_dir, data)

else:
    data = GET_request_server(rec_IP, rec_PORT, file_to_get, server_name)
    if check_answered_request(data, file_to_get):
        data = data.split(b'\n', 3)[3]
        create_file_in_dir(filename, '.', data)


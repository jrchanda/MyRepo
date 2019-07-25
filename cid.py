###############################################################################
# Note: The only API for public consumption is get_response_string(). Calling
# any other function in this file is prohibited and not supported.
#
# File Version: 2.0.0
###############################################################################

import subprocess, getpass, string, re, datetime, os, logging

logger = logging.getLogger(__name__)
host = "cid.cisco.com"

class cid_ret(object):
    def __init__(self, value, msg, resp):
        self.ret_value = value
        self.ret_msg = msg
        self.response = resp
        print('Executing script')

    def cid_print(self, msg):
        now = datetime.datetime.now()
        logger.info(msg)
        print (now.isoformat() + ": " + msg)

    def ssh_to_get_response(self, challenge, ticket, debug):
        port = "19027"

        # get index of end of challenge string
        end_of_challenge = challenge.find("DONE.")

        if end_of_challenge == -1:
            err_msg = "Challenge string incomplete. No \"DONE.\"."
            return cid_ret(1, err_msg, "")

        # remove any white space, extra, or invalid characters that may have been
        # added to the challenge string
        # then break the challenge string into an array delimited by newlines "\n"
        sub_string = re.sub('[^a-zA-Z0-9\n+/=]', '', challenge[0:end_of_challenge])
        challenge_string = sub_string.split('\n')
        # challenge_string = re.sub('[^a-zA-Z0-9\n+/=]', '',
        #                                    challenge[0:end_of_challenge])
        if len(challenge_string) == 0:
            return cid_ret(1, "ERROR: No challenge string", "")


        ssh_cmd = "ssh -p " + port + " " + host + " retrieve-response " + \
                    ticket + " "

        for line in challenge_string:
            ssh_cmd += " \"" + line + "\""
        print(ssh_cmd)
        p = subprocess.Popen(ssh_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (output, err) = p.communicate(timeout=15)
        print('Error output:')
        print(err.decode())

        print('Actual output:')
        print(output.decode())

        err = err.decode().split("\n")
        output = output.decode().split("\n")
        response = ""
        flag = 0
        error = 0
        stderr_msg = "Unknown Error: "

        if debug != 0:
            self.cid_print("Dumping SSH Connection Output:")

        for line in err:
            if debug != 0:
                self.cid_print("STDERR: " + line)

            stripped_line = line.strip()

            if stripped_line.find("No route to host") != -1:
                return cid_ret(1, "ERROR: No route to host.", "")
            elif stripped_line:
                error = 1
                stderr_msg += line + '\n'

        if error:
            return cid_ret(1, stderr_msg, "")

        for line in output:
            if debug != 0:
                self.cid_print("STDOUT: " + line)

            if flag == 0:
                if line.find("Internal Error") != -1:
                    return cid_ret(1,
                                "ERROR: Ticket may be expired.", "")

                if line.find("Invalid Challenge") != -1:
                    return cid_ret(1, "ERROR: Invalid Challenge.", "")

                if line.find("Failed to retrieve response") != -1:
                    return cid_ret(1, "ERROR: Failed To Retrieve Response.", "")

                if line.find("Invalid and Non-Printable Character Found:") != -1:
                    return cid_ret(1,
                            "ERROR: Challenge Contains Invalid Characters.", "")

                if line.find("Missing Options") != -1:
                    return cid_ret(1, "ERROR: No Challenge String", "")

                if line.find("Response String") != -1:
                    flag = 1
                    response += line + "\n"
            else:
                response += line + "\n"

        # Check For Response String Print
        if flag != 1:
            return cid_ret(1, "ERROR: Response Not Found.", "")

        # Get reponse string
        a = re.search(r'[\*]+(.*DONE.)', response, re.DOTALL)
        if a:
            response_string = '\n'.join(a.group(1).split('\n')[1:])
        else:
            return cid_ret(1, "ERROR: Unable to retrieve response", "")

        return cid_ret(0, "Success", response_string)

    def get_response_string(self, challenge, ticket_dir, debug):

        if debug == 1:
            self.cid_print("Debug Verbosity Enabled!!")

        try:
            ticket_files = os.listdir(ticket_dir)
            logger.info('ticket files:' + str(ticket_files))
        except:
            self.cid_print("Cannot list directory contents in " + str(ticket_dir))
            return "ERROR: Cannot list directory contents in " + ticket_dir

        for a_file in ticket_files:
            a_ticket = ticket_dir + "/" + a_file
            self.cid_print("Processing Ticket File: " + a_ticket)
            logger.info("Processing Ticket File: " + a_ticket)
            try:
                if os.path.isfile(a_ticket) != True:
                    self.cid_print(a_ticket + " is not a file. Skipping...")
                    logger.info(a_ticket + " is not a file. Skipping...")
                    continue
            except:
                self.cid_print("Cannot determine if " + a_ticket + " is a file or not." \
                            + " Skipping...")
                logger.info("Cannot determine if " + a_ticket + " is a file or not." \
                            + " Skipping...")
                continue

            try:
                fd = open(a_ticket, 'r')

            except:
                self.cid_print("Cannot open file: " + a_ticket + " Skipping ...")
                logger.info("Cannot open file: " + a_ticket + " Skipping ...")
                continue

            ticket_data = fd.read()
            fd.close()

            filtered_ticket_data = re.sub(r'\s+', "", ticket_data)
            results = re.search(r'[^0-9A-Za-z+/=]', filtered_ticket_data)

            if results:
                self.cid_print("File, " + a_ticket + " does not contain a valid ticket" \
                            + " Skipping...")
                continue

            self.cid_print(challenge)
            self.cid_print(filtered_ticket_data)
            ssh_ret = self.ssh_to_get_response(challenge, filtered_ticket_data, debug)

            if ssh_ret.ret_value:
                self.cid_print(ssh_ret.ret_msg + " Skipping ...")
            else:
                return ssh_ret.response

        return "ERROR: Cannot obtain response."


if __name__ == '__main__':
    print('In main calling')
    obj = cid_ret('10', 'Testing Message', True)
    obj.cid_print('Started Test To Get Response String')
    ticket_dir = '/data/home/jchanda/cid/tickets'
    debug = 1
    challenge = '''hez//wIAAABdGGXBy1JAWHa4qwB9a+Jy3GG3M5BaWg70CnanTtmXBA8H7R0hJgEA
nCMaxB30KFoCJA==
DONE.'''
    out = obj.get_response_string(challenge, ticket_dir, debug)
    print('Output of response string is:')
    print(out)

"""
    Velocity ReST Client
    This is Front end for Velocity ReST Full API
    Support python 2.7.16 to python 3+
"""


__Version__ = '0.1'
__Author__ = 'Poornima Wari'


from requests.auth import HTTPBasicAuth  # required for authentication
from datetime import datetime  # required to create log file based on current time and date


"""
    Modification history
    --------------------
    0.1 : 8/24/2021
           - Initial code    
"""


import requests  # required to interact with Velocity ReST Full API
import os  # required for log path
import logging  # required for logger
import json  # required for json format
import sys  # required to Trace the ERROR
import platform  # required to log the Python Version
import functools  # required for decorating the logs
# python2 support urlparse and python3 urllib.parse
# required to build the URL
try:
    from urllib.parse import urlunsplit
except ImportError:
    from urlparse import urlunsplit


# Helper functions
# Helper to decorate the logger
def log_decorator(function):
    """
        This definition will help us log the request and response of the function
    :param function: Name of the function
    :return: logs request and response
    """

    @functools.wraps(function)
    def inner_function(*args, **kwargs):
        # log the args and kwargs if any
        logging.info('Starting Function (' + function.__name__ + ') ' + str(args) + ' ' + str(kwargs))
        try:
            response = function(*args, **kwargs)
            logging.info('Response of (' + function.__name__ + ') ' + str(response))
        except:
            # log the exception
            logging.error('Error: {}.{},line:{}'.format(sys.exc_info()[0], sys.exc_info()[1],
                                                        sys.exc_info()[2].tb_lineno))
            raise
        return response

    return inner_function


def process_response(raw_response):
    """
        This definition will help process the raw response and returns out in json/text
    :param raw_response: response of http verbs
    :return: return response in json/text
    """
    content_type = raw_response.headers.get('content-type')
    response = ''
    if 'text' in content_type.lower():
        response = raw_response.text
    elif 'application/json' in content_type.lower():
        response = raw_response.json
    else:
        response = raw_response.content
    return response


class Velocity:
    """
        This is python ReST Client for Velocity ReST API
        Supports HTTP VERBS : GET,PUT,POST and DELETE

        Command/Syntax:

             velocity_object = Velocity('ps-production-velocity.spirenteng.com', token=token)

             # get the version (html format)
             end_points = '/velocity'
             version_html = velocity_object.get(end_points)

             # get the topology tbml format
             reservation_id =<you can get it from velocity environ>
             end_point = 'velocity/api/reservation/v17/reservation/' + reservation_id + '/topology'
             tbml_format = velocity.get(end_point)

    """

    def __init__(self, velocity_domain_name, user_name='', password='', log_level='INFO',
                 log_path='', scheme='https', token=''):
        """
            init definition
            Note : velocity environ gives you the token and reservation id
                    if you want to run stand along from your system you can pass username and password
        :param velocity_domain_name: velocity domain name
        :param scheme: https
        :param user_name: username
        :param password: password
        :param log_level: default its INFO , you can pass DEBUG,ERROR or CRITICAL
        :param log_path: log path directory # default it creates logs folder,
                         under that creates logfile with current time and date
        :param token: velocity environ provides you the token
        """

        # set initial values
        self.log_path = log_path
        self.velocity_domain_name = velocity_domain_name
        self.user_name = user_name
        self.password = password

        # create logs folder
        self.log_path = os.path.abspath('logs')

        # get the current time and date to create the log file
        now = datetime.now()
        time_date = now.strftime("H%M%S%m%d%Y")

        # override the user specified log path
        if log_path:
            self.log_path = os.path.join(log_path, 'logs')

        # crete the log folder if it doesn't exist
        if not os.path.exists(self.log_path):
            os.mkdir(self.log_path)

        self.log_path = os.path.expanduser(self.log_path)

        # create log file with current time date
        self.log_file = os.path.join(self.log_path + '/velocity_rest_client' + time_date + '.log')

        # set the log-level
        if log_level.lower() == 'debug':
            self.log_level = 'DEBUG'
        elif log_level.lower() == 'error':
            self.log_level = 'ERROR'
        elif log_level.lower() == 'critical':
            self.log_level = 'CRITICAL'
        elif log_level.lower() == 'warning':
            self.log_level = 'WARNING'
        else:
            self.log_level = 'INFO'

        # set the logger format , this is velocity compatible
        logging.basicConfig(filename=self.log_file, filemode='w', level=self.log_level,
                            format='%(asctime)s %(levelname)-8s %(message)s')

        # crete logger object
        logger = logging.getLogger(self.log_file)

        # log python version
        logging.info('Python Version ' + platform.python_version())
        logging.info('Executing Velocity __init__ ')

        # suppress all the logging from deeply rooted modules but the critical
        # get the root and set it to critical
        logging.getLogger('requets').setLevel(logging.CRITICAL)

        # build the api ex: https://<velocity domain >
        self.__url = urlunsplit((scheme, velocity_domain_name, '', '', ''))
        logging.info('URL ' + self.__url)

        # need token for authorization
        self.__token = token

        # if the token is not passed, get one
        if not self.__token:
            logging.info('Getting the velocity token with User ' + self.user_name + ' Password ' + self.password)
            response = requests.get(self.__url + '/velocity/api/auth/v2/token',
                                    auth=HTTPBasicAuth(self.user_name, self.password))

            # error handling in-case of failure
            if not response.ok:
                try:
                    error_content = response.content
                    response.raise_for_status()
                except Exception as error:
                    logging.CRITICAL('Failed to Authorize ' + str(error) + '\n' + str(error_content))
                    raise requests.HTTPError(error, error_content)

            logging.info('Successfully Authorized')
            self.__token = response.json()['token']

        # create session
        self.__session = requests.session()
        self.__session.headers.update({'X-Auth-Token': self.__token})

    @log_decorator
    def put(self, end_points, **kwargs):
        """
            This is http put method
        :param end_points: end url
        :param kwargs: payload={}
        :return: response
        """

        response = self.process_request('put', end_points, **kwargs)
        return response

    @log_decorator
    def post(self, end_points, **kwagrs):
        """
            This is http post method
        :param end_points: end url
        :param kwagrs: data/payload /file_name {Ex : files=file_name}
        :return: response
        """

        response = self.process_request('post', end_points, **kwagrs)
        return response

    @log_decorator
    def get(self, end_points, **kwargs):
        """
            This is http get method
        :param end_points: end url
        :param kwargs: data or payload
        :return: response
        """

        response = self.process_request('get', end_points, **kwargs)
        return response

    @log_decorator
    def delete(self, end_points, **kwargs):
        """
            This is http delete method
        :param end_points: end url
        :param kwargs: data or payload
        :return: response
        """

        response = self.process_request('delete', end_points, **kwargs)
        return response

    def process_request(self, http_method, end_points, **kwargs):
        """
            This method will help process the request and returns the response
        :param http_method: get/put/post/delete
        :param end_points: url end point . refer velocity API doc
        :param kwargs: data/payload json format
        :return: returnce the response
        """
        # check if url end point starts with /
        if not end_points.startswith('/'):
            end_points = '/' + end_points

        # add the end_point to url
        url = self.__url + end_points

        payload = {}
        file_data = None
        raw_response = None

        # check for the payload and files in kwargs
        if len(list(kwargs.keys())) > 0:
            for key1 in kwargs.keys():
                if 'payload' in key1 or 'data' in key1:
                    # convert python object to json string
                    payload = json.dumps(kwargs[key1])
                elif 'file' in key1:
                    # in case you want to post the file
                    file_name = kwargs[key1]
                    file_data = [('mapFileFormFile', (file_name, open(file_name, 'rb'), 'application/json'))]

        # verify http method and process
        if http_method.lower() == 'put':
            raw_response = self.__session.put(url, data=payload)
        elif http_method.lower() == 'post':
            raw_response = self.__session.post(url, data=payload, files=file_data)
        elif http_method.lower() == 'get':
            raw_response = self.__session.get(url, data=payload)
        elif http_method.lower() == 'delete':
            raw_response = self.__session.delete(url)
        else:
            # method doesnt exist raise exception
            logging.ERROR('HTTP Method ' + http_method + ' doesnt exist. Must be "GET PUT POST and DELETE"')
            raise ValueError('ERROR : The HTTP-VERB ' + http_method + ' not found. Must be "GET PUT POST and DELETE"')

        if not raw_response.ok:
            # ERROR handling
            try:
                raw_response.raise_for_status()
            except Exception as error_massage:
                logging.critical(str(error_massage))
                raise requests.HTTPError(error_massage)
        # process the response
        end_result = process_response(raw_response)
        return end_result


# main function
def main():
    # velocity = Velocity('ps-production-velocity.spirenteng.com', user_name='tech01', password='spirent')

    # testing with token
    token = 'eyJwYWNrZXQiOiJ7XCJpZFwiOlwicHdhcmlcIixcInVzZXJfbmFtZVwiOlwicHdhcmlcIixcImRvbWFpblwiOlwibGRhcFwiLFwic3' \
            'RhcnRfdGltZVwiOjE2Mjg3ODUwMjIsXCJleHBpcmF0aW9uXCI6MTY2MDMyMTMyMn0iLCJzaWduYXR1cmUiOiIyQ0YwNDM0QUIyRTk5' \
            'MEE0N0YzNjU5N0IxNkMyM0QyOUVDNkZFOUUwNzFGQjRGQ0FBMUVDMDNFM0FENkNGMDVDRUFFNjgxNEI0RkI0MDg0NTE5RTRENjlFQUM' \
            'zRjhBNzYyMDZGRUMxNzJCOTIzNzNDODQ3OEVFMERFQjMxMUM5NERFMkVBQjZBQ0FDQkVGMDkzQzExQTMyOUNERDUyMjQwNEEwNjc0OTA' \
            'yRjc5MUM0MDg3RTE3NTc2NDJDMDI2RTAyMEYxNzUyQjExQjE2QjZEQjc4RDczNEZCMDlEMDVDNUE5QTU2REQ5NTZCOTMwOEJDMEJCNU' \
            'ExQkI0OEVBRkE5NDQ3Nzc5RkU4MTkyRENBQjIyMjUxNERFNjJFNzlDMTgzMEU4RUFFOTcxMzE1OTkwNkFBRjRGQzUwRTdCMjNFRjI5RT' \
            'BFNjBCOUI2MENGOUIzNjk4RDVFQkNFNkIxNjUyODU2Qjk1QTZBRUVENDU0RkFCNEE1RTcyOUFBMzgxRTE5Mjk2QUEwQ0M2NjU2NzYwM0' \
            'Q0NEM3RkFGMjdDOTUwNjQ2NTI1QzlEN0Q1MEFFODA3NjVENTU3M0E0QzgzODNEMTM4RDA2NEEwODYwMjNDQkFCNjVBNUYwQUYyNDUyND' \
            'I1NzM3QjgwRTZGRTkzODYwNERENzRDNkY4NDk1Qzk3NiJ9'

    velocity = Velocity('ps-production-velocity.spirenteng.com', token=token)
    version_html = velocity.get('/velocity')

    reservation_id = '619cb4de-b354-4d83-8dc5-d617470838df'
    end_point = 'velocity/api/reservation/v17/reservation/' + reservation_id + '/topology'

    tbml_format = velocity.get(end_point)

    return tbml_format.decode()


if __name__ == "__main__":
    topology = main()
    print(topology)
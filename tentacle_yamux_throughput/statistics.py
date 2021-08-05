import re
import sys

if __name__ == "__main__":
    with open('throughput_server.log', 'r') as f:
        data = [line for line in f if '10 secs' in line]

    low_stream_req, low_stream_resp = map(sum, zip(
        *(map(int, re.findall(r'req (\d*)?, resp (\d*)?', i).pop()) for i in data[1:29])))
    high_stream_req, high_stream_resp = map(sum, zip(
        *(map(int, re.findall(r'req (\d*)?, resp (\d*)?', i).pop()) for i in data[-29:-1])))
    low_resp_req = low_stream_resp / low_stream_req
    high_resp_req = high_stream_resp / high_stream_req
    high_low_req = high_stream_req / low_stream_req
    high_low_resp = high_stream_resp / low_stream_resp

    print("Statistics Data")
    print("-------")
    print("{:<7} | {:<10} | {:<10} | {:<10}".format(
        "streams", "req", "resp", "resp/req"))
    print("{:<7} | {:<10} | {:<10} | {:<10.2%}".format(
        20, low_stream_req, low_stream_resp, low_resp_req))
    print("{:<7} | {:<10} | {:<10} | {:<10.2%}".format(
        2000, high_stream_req, high_stream_resp, high_resp_req))
    print("------")
    print("req_of_2000  / req_of_20  = {:.2%}".format(high_low_req))
    print("resp_of_2000 / resp_of_20 = {:.2%}".format(high_low_resp))

    if any(filter(lambda x: x < 0.8, [low_resp_req, high_resp_req, high_low_req, high_low_resp])):
        sys.exit(-1)

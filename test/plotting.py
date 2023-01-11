import os

import matplotlib.pyplot as plt


def handle_log_time(time_str):
    ms = time_str.split(',')
    date = ms[0].split(' ')
    year, month, day = date[0].split('-')
    hour, minute, second = date[1].split(':')
    millisecond = ms[1]
    year, month, day, hour, minute, second, millisecond \
        = int(year), int(month), int(day), int(hour), int(minute), int(second), int(millisecond)
    time_cnt = millisecond + second * 1000 + minute * 60 * 1000 + \
               hour * 60 * 60 * 1000 + day * 24 * 60 * 60 * 1000 + \
               month * 30 * 24 * 60 * 60 * 1000 + \
               year * 12 * 30 * 24 * 60 * 60 * 1000
    return time_cnt


def handle_log(path):
    time_winsize = {}
    file = open(path, encoding='utf-8', mode='r')
    infos = file.readlines()
    start, end = 0, 0
    for i in range(len(infos)):
        info = infos[i]
        split = info.split(" -+- ")
        time_cnt = handle_log_time(split[0])
        msg = split[-1].replace("\n", "").split(" ")
        winsize = int(msg[-1])
        if i == 0:
            start = time_cnt
        if i == len(infos) - 1:
            end = time_cnt - start
        time_winsize[time_cnt - start] = winsize
    temp = 0
    x_axis, y_axis = [], []
    for i in range(end):
        item = time_winsize.get(i)
        if item is not None:
            temp = i
        else:
            item = time_winsize.get(temp)
        x_axis.append(i)
        y_axis.append(item)
    return x_axis, y_axis


dirname = '../log/plotting'
dirs = os.listdir(dirname)

for d in dirs:
    peer_dir = os.path.join(dirname, d)
    if os.path.isdir(peer_dir):
        for log in os.listdir(peer_dir):
            if log.endswith(".png"):
                continue
            fig_name = log.replace(".log", "") + '.png'
            fig_path = os.path.join(peer_dir, fig_name)
            log_path = os.path.join(peer_dir, log)
            x_axis, y_axis = handle_log(log_path)
            plt.figure()
            plt.plot(x_axis, y_axis, '-', color='#4169E1', alpha=0.8, linewidth=1, label="WINSIZE")
            plt.legend(loc="upper right")
            plt.xlabel("Time")
            plt.ylabel("WINSIZE")
            plt.title("WINSIZE")
            plt.savefig(fig_path)
            plt.close()

#encoding:utf8
import urllib2
from multiprocessing.dummy import Pool as ThreadPool
import datetime, time, os, random

aaa = 100001

urls = [
  'http://www.baidu.com/s?wd=1',
  'http://www.baidu.com/s?wd=2',
  'http://www.baidu.com/s?wd=3',
  'http://www.baidu.com/s?wd=4',
  'http://www.baidu.com/s?wd=5',
  'http://www.baidu.com/s?wd=6',
  'http://www.baidu.com/s?wd=7',
  'http://www.baidu.com/s?wd=8',
  # 'http://www.baidu.com/s?wd=9',
  # 'http://www.baidu.com/s?wd=a',
  # 'http://www.baidu.com/s?wd=b',
  # 'http://www.baidu.com/s?wd=c',
  # 'http://www.baidu.com/s?wd=d',
  # 'http://www.baidu.com/s?wd=e',
  # 'http://www.baidu.com/s?wd=f',
  # etc..
]


def do_print2(ts, ss):
    global aaa
    time.sleep(random.random() * random.random())
    # time.sleep(2)
    print "%s:%s" % (ts, ss)


def do_print(ts, ss):
    global aaa
    time.sleep(random.random() * random.random())
    # time.sleep(2)
    print "%s:%s:%s" % (ts, ss, aaa)
    aaa += 1

    ts = 300001

    # Make the Pool of workers
    pool = ThreadPool(4)
    # Open the urls in their own threads
    # and return the results
    results = pool.map(lambda url, ts=ts+aaa: do_print2(ts, url), urls)


ts = 100001

# Make the Pool of workers
pool = ThreadPool(18)
# Open the urls in their own threads
# and return the results
results = pool.map(lambda url, ts=ts: do_print(ts, url), urls)
#close the pool and wait for the work to finish
# pool.close()
# pool.join()

print "zzzzzzzzzzzzzz"

ts = 200001

# Make the Pool of workers
pool = ThreadPool(4)
# Open the urls in their own threads
# and return the results
results = pool.map(lambda url, ts=ts: do_print(ts, url), urls)



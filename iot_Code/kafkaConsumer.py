# -*- coding: utf-8 -*-
"""
Created on Fri Dec 28 13:51:43 2018

@author: Innive
"""

# spark-submit --packages org.apache.spark:spark-streaming-kafka-0-8_2.11:2.4.3,org.mongodb.spark:mongo-spark-connector_2.11:2.2.0 kafkaConsumer.py 10.176.148.202:2181 IOT

import sys
import json
from pyspark import SparkContext
from pyspark.sql import SparkSession
from pyspark.streaming import StreamingContext
from pyspark.streaming.kafka import KafkaUtils
from pyspark.ml import  PipelineModel
import socketClient, Properties, CryptoHelper
from Job import Job
from datetime import timedelta



soc = socketClient.connect_to_server(port=20001)


def process(time, rdd):        
        if (not rdd.isEmpty()):
            #df = spark.createDataFrame(rdd, ["deviceId", "deviceType","data"] )
            df = spark.createDataFrame(rdd, ["deviceId", "deviceType","data"] )
            #predictions.show()
            df.write.format("com.mongodb.spark.sql.DefaultSource").mode("append").save()


def send_to_sgx(time, rdd):
    if (not rdd.isEmpty()):
        jd = rdd.first()
        print("JSON: ", jd)
        socketClient.send_to_server(soc, jd)


def send_to_spark(time, rdd):
    if (not rdd.isEmpty()):
        jd = json.dumps(CryptoHelper.aes_gcm_decryption_python(rdd.first()))
        print("JSON: ", jd)


def create_listener():
    socketClient.receive_from_server(soc)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: kafka_wordcount.py <zk> <topic>", file=sys.stderr)
        exit(-1)

    job = Job(interval=timedelta(seconds=Properties.WAIT_TIME_SECONDS), execute=create_listener)
    job.start()

    sc = SparkContext(appName="PythonStreamingIOT")
    sc.setLogLevel("ERROR")
    spark = SparkSession.builder.appName("myApp").config("spark.mongodb.input.uri", "mongodb://127.0.0.1/IOT.hubData2").config("spark.mongodb.output.uri", "mongodb://127.0.0.1/IOT.hubData2").getOrCreate()
    ssc = StreamingContext(sc, 1)
    #model=PipelineModel.load("PreProcessfittedPipelineSaved")
    zkQuorum, topic = sys.argv[1:]

    kvs = KafkaUtils.createStream(ssc, zkQuorum, "spark-streaming-consumer", {topic: 1})

    #documents_tuple = kvs.map(lambda line: ((line[1].split("||")[0]), line[1].split("||")[1],line[1].split("||")[2]))
    # documents_tuple=kvs.map(lambda line:(json.loads(line[1])['deviceId'],json.loads(line[1])['deviceType'],json.dumps(json.loads(line[1])['data'])))


    # documents_tuple.pprint()
    if Properties.IS_SGX:
        documents_tuple = kvs.map(lambda line: json.dumps(json.loads(line[1])))
        documents_tuple.foreachRDD(send_to_sgx)
    else:
        documents_tuple = kvs.map(lambda line: line[1])
        documents_tuple.foreachRDD(send_to_spark)

    ssc.start()
    ssc.awaitTermination()# -*- coding: utf-8 -*-

    soc.close()



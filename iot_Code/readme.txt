flaskApp is generating the dummy encrypted data.
Then start the zookeeper and Kafka Server
Then start the kafkProd script file.
Then start the MongoDB server.
Then to run the kafka Consumer, submit the following in the command prompt

spark-submit --packages org.apache.spark:spark-streaming-kafka-0-8_2.11:2.4.3,org.mongodb.spark:mongo-spark-connector_2.11:2.2.0 kafkaConsumer.py localhost:2181 IOT

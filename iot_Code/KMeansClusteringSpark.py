import json
from pyspark import SparkContext, SparkConf
from pyspark.sql import SparkSession
from pyspark.streaming import StreamingContext
from pyspark.streaming.kafka import KafkaUtils
from pyspark.ml import  PipelineModel
import Properties, CryptoHelper, Helper
from pymongo import MongoClient
from sklearn import preprocessing
import numpy as np
from math import sqrt, ceil, floor
from pyspark.mllib.clustering import KMeans, KMeansModel,StreamingKMeans, StreamingKMeansModel

from sklearn.datasets import make_blobs
from sklearn.cluster import KMeans as KMeans_SK
from sklearn.metrics import silhouette_samples, silhouette_score

import matplotlib.pyplot as plt
import matplotlib.cm as cm
from mpl_toolkits.mplot3d import Axes3D



client = MongoClient('10.176.148.202', 27017)
mydatabase = client['IOT']
mycollection = mydatabase['foobot2']
TRAIN_DATA_LIMIT = 1000
TOTAL_DATA = 0

scaler = None
clusters = None
IS_CLUSTER_BUILD = False


def error(point):
    center = clusters.centers[clusters.predict(point)]
    return sqrt(sum([x ** 2 for x in (point - center)]))


def get_data_from_db():
    cursor = mycollection.find({})
    record_list = []
    count = 0
    for item in cursor:
        data_json = json.loads(item['data'])
        values_list = [float(data_json['hum']), float(data_json['tmp']), float(data_json['co2'])]
        if count <= TRAIN_DATA_LIMIT:
            print("Values: ", values_list)
        record_list.append(values_list)
        count +=1
    print("Total Documents in Collection: ", mycollection.count_documents({}))
    # Pre-process data
    record_list = record_list[0:TRAIN_DATA_LIMIT]
    record_list = np.array(record_list)
    global scaler
    scaler = preprocessing.StandardScaler().fit(record_list)
    record_scaled = scaler.transform(record_list)
    return record_scaled


def parse_data_point(data):
    data_json = Helper.get_json_data(data)
    values_list = [float(data_json['data']['hum']), float(data_json['data']['tmp']), float(data_json['data']['co2'])]
    record_list = np.array(values_list).reshape(1, -1)
    record_scaled = scaler.transform(record_list)
    return record_scaled


def build_clusters_offline(sc):
    records = get_data_from_db()
    recordRDD = sc.parallelize(records)
    global clusters
    clusters = KMeans.train(recordRDD, k=5, maxIterations=10, initializationMode="random")
    global IS_CLUSTER_BUILD
    IS_CLUSTER_BUILD = True


def run_kmeans(sc, data):
    if IS_CLUSTER_BUILD == False:
        build_clusters_offline(sc)
    data_scaled = parse_data_point(data)
    ret = clusters.predict(sc.parallelize(data_scaled))
    print("******** Return value: ")
    ret.foreach(print)


def plot_silhoutte(X):
    range_n_clusters = [2, 3, 4, 5, 6]

    for n_clusters in range_n_clusters:
        # Create a subplot with 1 row and 2 columns
        fig, (ax1, ax2) = plt.subplots(1, 2)
        fig.set_size_inches(18, 7)

        # The 1st subplot is the silhouette plot
        # The silhouette coefficient can range from -1, 1 but in this example all
        # lie within [-0.1, 1]
        ax1.set_xlim([-0.1, 1])
        # The (n_clusters+1)*10 is for inserting blank space between silhouette
        # plots of individual clusters, to demarcate them clearly.
        ax1.set_ylim([0, len(X) + (n_clusters + 1) * 10])

        # Initialize the clusterer with n_clusters value and a random generator
        # seed of 10 for reproducibility.
        clusterer = KMeans_SK(n_clusters=n_clusters, random_state=10)
        cluster_labels = clusterer.fit_predict(X)

        # The silhouette_score gives the average value for all the samples.
        # This gives a perspective into the density and separation of the formed
        # clusters
        silhouette_avg = silhouette_score(X, cluster_labels)
        print("For n_clusters =", n_clusters,
              "The average silhouette_score is :", silhouette_avg)

        # Compute the silhouette scores for each sample
        sample_silhouette_values = silhouette_samples(X, cluster_labels)

        y_lower = 10
        for i in range(n_clusters):
            # Aggregate the silhouette scores for samples belonging to
            # cluster i, and sort them
            ith_cluster_silhouette_values = \
                sample_silhouette_values[cluster_labels == i]

            ith_cluster_silhouette_values.sort()

            size_cluster_i = ith_cluster_silhouette_values.shape[0]
            y_upper = y_lower + size_cluster_i

            color = cm.nipy_spectral(float(i) / n_clusters)
            ax1.fill_betweenx(np.arange(y_lower, y_upper),
                              0, ith_cluster_silhouette_values,
                              facecolor=color, edgecolor=color, alpha=0.7)

            # Label the silhouette plots with their cluster numbers at the middle
            ax1.text(-0.05, y_lower + 0.5 * size_cluster_i, str(i))

            # Compute the new y_lower for next plot
            y_lower = y_upper + 10  # 10 for the 0 samples

        ax1.set_title("The silhouette plot for the various clusters.")
        ax1.set_xlabel("The silhouette coefficient values")
        ax1.set_ylabel("Cluster label")

        # The vertical line for average silhouette score of all the values
        ax1.axvline(x=silhouette_avg, color="red", linestyle="--")

        ax1.set_yticks([])  # Clear the yaxis labels / ticks
        ax1.set_xticks([-0.1, 0, 0.2, 0.4, 0.6, 0.8, 1])

        # 2nd Plot showing the actual clusters formed
        cmap = cm.get_cmap("Spectral")
        colors = cmap(cluster_labels.astype(float) / n_clusters)
        # ax2.scatter(X[:, 0], X[:, 1], marker='.', s=30, lw=0, alpha=0.7,
        #             c=colors, edgecolor='k')
        ax2.scatter(X[:, 0], X[:, 1], marker='.', s=30, lw=0, alpha=0.7,
                    c=colors, edgecolor='k')

        # Labeling the clusters
        centers = clusterer.cluster_centers_
        # Draw white circles at cluster centers
        ax2.scatter(centers[:, 0], centers[:, 1], marker='o',
                    c="white", alpha=1, s=200, edgecolor='k')

        for i, c in enumerate(centers):
            ax2.scatter(c[0], c[1], marker='$%d$' % i, alpha=.5,
                        s=50, edgecolor='k')

        ax2.set_title("The visualization of the clustered data.")
        ax2.set_xlabel("Feature space for the 1st feature")
        ax2.set_ylabel("Feature space for the 2nd feature")

        plt.suptitle(("Silhouette analysis for KMeans clustering on sample data "
                      "with n_clusters = %d" % n_clusters),
                     fontsize=14, fontweight='bold')

    plt.show()


def plot_silhoutte_3d(X):
    range_n_clusters = [2, 3, 4, 5, 6, 10]
    for n_clusters in range_n_clusters:
        fig = plt.figure()
        ax = fig.add_subplot(111, projection='3d')

        clusterer = KMeans_SK(n_clusters=n_clusters, random_state=10)
        cluster_labels = clusterer.fit_predict(X)

        silhouette_avg = silhouette_score(X, cluster_labels)
        print("For n_clusters =", n_clusters,
              "The average silhouette_score is :", silhouette_avg)

        colors = cm.nipy_spectral(cluster_labels.astype(float) / n_clusters)
        ax.scatter(X[:, 0], X[:, 1], X[:, 2], marker='.', s=30, lw=0, alpha=0.7,
                    c=colors, edgecolor='k')

        centers = clusterer.cluster_centers_
        # Draw white circles at cluster centers
        ax.scatter(centers[:, 0], centers[:, 1], centers[:, 2]+0.5, marker='o',
                    c="black", alpha=.2, s=200, edgecolor='k')

        for i, c in enumerate(centers):
            ax.scatter(c[0], c[1], c[2]+0.5, marker='$%d$' % i, alpha=.5,
                        s=50, edgecolor='k')

        ax.set_title("The visualization of the clustered data.")
        ax.set_xlabel("Feature space for the 1st feature")
        ax.set_ylabel("Feature space for the 2nd feature")

        plt.suptitle(("KMeans clustering on sample data "
                      "with n_clusters = %d" % n_clusters),
                     fontsize=14, fontweight='bold')
        plt.show()


def test_silhouette():
    X, yyy = make_blobs(n_samples=500,
                      n_features=2,
                      centers=4,
                      cluster_std=1,
                      center_box=(-10.0, 10.0),
                      shuffle=True,
                      random_state=1)  # For reproducibility

    X = get_data_from_db()
    plot_silhoutte_3d(X)



def test_kmeans():
    records = get_data_from_db()

    conf = SparkConf().setAppName("testingClusters").setMaster("local[*]")
    sc = SparkContext(conf=conf)
    sc.setLogLevel("ERROR")

    k_value = ceil(len(records)/100)
    print("K value = ", k_value)
    print("Total instances = ", len(records))

    recordRDD = sc.parallelize(records)
    global clusters
    clusters = KMeans.train(recordRDD, k=k_value, maxIterations=100, initializationMode="random")
    print("Total clusters: ", len(clusters.clusterCenters))

    sse = clusters.computeCost(recordRDD)
    print("********** SSE Cost: ", sse)
    WSSSE = recordRDD.map(lambda point: error(point)).reduce(lambda x, y: x + y)
    print("********** Within Set Sum of Squared Error = " + str(WSSSE))

    sample_data = np.array([46.5, 23.0, 1034.0]).reshape(1, -1)
    record_scaled = scaler.transform(sample_data)
    print("Scaled Record: ", record_scaled)
    ret = clusters.predict(sc.parallelize(record_scaled))
    print("******** Predicted cluster index: ")
    ret.foreach(print)

    for center in clusters.clusterCenters:
        distance = np.linalg.norm(center - record_scaled)
        similarity = 1 / (1 + distance)
        print(center, distance, similarity)


def test_streaming_kmeans():
    records = get_data_from_db()

    conf = SparkConf().setAppName("testingClusters").setMaster("local[2]")
    sc = SparkContext(conf=conf)
    sc.setLogLevel("ERROR")

    initCenters = [[0.0, 0.0, 0.0], [1.0, 1.0, 1.0], [0.5, 0.5, 0.5]]
    initWeights = [1.0, 1.0, 1.0]
    stkm = StreamingKMeansModel(initCenters, initWeights)
    recordRDD = sc.parallelize(records)
    stkm = stkm.update(data=recordRDD, decayFactor=1.0, timeUnit=u"batches")

    for center in stkm.centers:
        print(center)

    sample_data = np.array([46.5, 23.0, 1034.0]).reshape(1, -1)
    record_scaled = scaler.transform(sample_data)
    print("Scaled Record: ", record_scaled)
    ret = stkm.predict(sc.parallelize(record_scaled))
    print("******** Predicted cluster index: ")
    ret.foreach(print)
    for center in stkm.centers:
        distance = np.linalg.norm(center - record_scaled)
        similarity = 1 / (1 + distance)
        print(center, distance, similarity)

    stkm = stkm.update(sc.parallelize(record_scaled), 1.0, u"points")

    sample_data = np.array([46.2, 23.5, 1034.32]).reshape(1, -1)
    record_scaled = scaler.transform(sample_data)
    print("Scaled Record: ", record_scaled)
    ret = stkm.predict(sc.parallelize(record_scaled))
    print("******** Predicted cluster index: ")
    ret.foreach(print)
    for center in stkm.centers:
        distance = np.linalg.norm(center - record_scaled)
        similarity = 1 / (1 + distance)
        print(center, distance, similarity)




if __name__ == '__main__':
    # To run main: spark-submit KMeansClusteringSpark.py
    # test_kmeans()
    # test_streaming_kmeans()
    test_silhouette()



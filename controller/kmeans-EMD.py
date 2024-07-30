import numpy as np
import random
import matplotlib.pyplot as plt
import csv
import scipy.stats

def loadTrainData(fileName):
    with open(fileName, encoding='UTF-8') as S1R:
        reader = csv.reader(S1R)
        for row in reader:
            #print(row[1])
            sum_row=float(row[1])+float(row[2])+float(row[3])+float(row[4])+float(row[5])+float(row[6])+float(row[7])+float(row[8])+float(row[9])+float(row[10])+float(row[11])
            TrainData.append([float(row[1])/sum_row,float(row[2])/sum_row,float(row[3])/sum_row,float(row[4])/sum_row,float(row[5])/sum_row,float(row[6])/sum_row,float(row[7])/sum_row,float(row[8])/sum_row,float(row[9])/sum_row,float(row[10])/sum_row,float(row[11])/sum_row])


def loadTestData(fileName):
    with open(fileName, encoding='UTF-8') as S1R:
        reader = csv.reader(S1R)
        for row in reader:
            #print(row[1])
            sum_row=float(row[1])+float(row[2])+float(row[3])+float(row[4])+float(row[5])+float(row[6])+float(row[7])+float(row[8])+float(row[9])+float(row[10])+float(row[11])
            TestData.append([float(row[1])/sum_row,float(row[2])/sum_row,float(row[3])/sum_row,float(row[4])/sum_row,float(row[5])/sum_row,float(row[6])/sum_row,float(row[7])/sum_row,float(row[8])/sum_row,float(row[9])/sum_row,float(row[10])/sum_row,float(row[11])/sum_row])
            TestLabel.append(int(row[12]))

def EMD(point1,point2):# Calculate distance (Wasserstein distance)
    # dists = [i for i in range(len(point1))] #(1)linear
    # dists=[0,2,4,8,16,32,64,128,256,512,1024] #(2)exponent
    dists=[0,1,4,9,16,25,36,49,64,81,100] #(3)square
    D = scipy.stats.wasserstein_distance(dists, dists, point1, point2)
    return D


def distance(point1, point2):  # alculate distance (Euclidean distance)
    return np.sqrt(np.sum((point1 - point2) ** 2))


def k_means(data, k, max_iter=10000):
    centers = {}  # initial cluster center
    # randomly selecting k samples as the initial cluster centersr
    n_data = data.shape[0]  # number of samples
    for idx, i in enumerate(random.sample(range(n_data), k)):
        # The value range of idx is [0, k-1], representing the number of cluster centers; Data [i] is a randomly selected sample used as the clustering center
        centers[idx] = data[i]

        # start iterating
    for i in range(max_iter):  
        print("start iteration No {}".format(i + 1))
        clusters = {}  # Cluster result, index idx of cluster center ->[sample set]
        for j in range(k):  # Initialize as an empty list
            clusters[j] = []
            clusters[j].append(centers[j])

        for sample in data:  # Traverse each sample
            distances = []  # Calculate the distance from the sample to each cluster center (there will only be k elements)
            for c in centers:  # Traverse each cluster center
                # Add the distance from the sample point to the cluster center
                distances.append(EMD(sample, centers[c]))
            idx = np.argmin(distances)  # Index of minimum distance
            clusters[idx].append(sample)  # Add the sample to the idxth cluster center

        pre_centers = centers.copy()  # Record the previous cluster center points

        for c in clusters.keys():
            # Recalculate the center point (calculate the mean of all samples in the cluster center)
            centers[c] = np.mean(clusters[c], axis=0)

        is_convergent = True
        for c in centers:
            if EMD(pre_centers[c], centers[c]) > 1e-5:  # Has the center point changed
                is_convergent = False
                break
        if is_convergent == True:
            # If the new and old cluster centers remain unchanged, the iteration stops
            break
    return centers, clusters


def predict(p_data, centers):  # Predict the class where the new sample point is located
    # Calculate the distance from p to each cluster center, and then return the cluster with the minimum distance.
    distances = [EMD(p_data, centers[c]) for c in centers]
    return np.argmin(distances)


TrainData=[]
TestData=[]
TestLabel=[]

if __name__ == '__main__':

    loadTrainData("D:\\k5\\train-k5.csv")
    x=np.array(TrainData)
    centers,clusters=k_means(x,2)

    print(centers)

    loadTestData("D:\\k5\\test-k5.csv")
    print("TestLable",TestLabel)
    y=np.array(TestData)
    TestSampleLen=y.shape[0]
    TruePredict=0
    TP=0
    TN=0
    FP=0
    FN=0
    for i in range (0,TestSampleLen):
        predict_result=predict(y[i],centers)
        if(predict_result==TestLabel[i]):
            #print(predict_result,TestLabel[i],"True")
            TruePredict=TruePredict+1
        #else:
            #print(predict_result,TestLabel[i],"False")

        if(predict_result==1 and TestLabel[i]==1):
            TP += 1
        elif(predict_result==0 and TestLabel[i]==1):
            FN += 1
        elif (predict_result == 1 and TestLabel[i] == 0):
            FP += 1
        else:
            TN += 1

    print("TP:",TP)
    print("TN",TN)
    print("FP:",FP)
    print("FN:",FN)
    accuracy=((TP+TN)/(TP+TN+FP+FN))*100
    precision=(TP /(TP + FP) )* 100
    recall=(TP /(TP + FN) )* 100
    f1=(2*precision*recall)/(precision+recall)
    print("Accuracy:",accuracy)
    print("precision:", precision)
    print("recall:", recall)
    print("f1:", f1)

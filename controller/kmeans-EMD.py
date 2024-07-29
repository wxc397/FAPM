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

def EMD(point1,point2):#计算距离（wasserstein距离）
    #P = np.array([1, 2, 1, 0, 0, 0])
    #Q = np.array([0, 0, 0, 1, 2, 1])
    # dists = [i for i in range(len(point1))] #(1)linear
    # dists=[0,2,4,8,16,32,64,128,256,512,1024] #(2)exponent
    dists=[0,1,4,9,16,25,36,49,64,81,100] #(3)square
    D = scipy.stats.wasserstein_distance(dists, dists, point1, point2)
    return D


def distance(point1, point2):  # 计算距离（欧几里得距离）
    return np.sqrt(np.sum((point1 - point2) ** 2))


def k_means(data, k, max_iter=10000):
    centers = {}  # 初始聚类中心
    # 初始化，随机选k个样本作为初始聚类中心。 random.sample(): 随机不重复抽取k个值
    n_data = data.shape[0]  # 样本个数
    for idx, i in enumerate(random.sample(range(n_data), k)):
        # idx取值范围[0, k-1]，代表第几个聚类中心;  data[i]为随机选取的样本作为聚类中心
        centers[idx] = data[i]

        # 开始迭代
    for i in range(max_iter):  # 迭代次数
        print("开始第{}次迭代".format(i + 1))
        clusters = {}  # 聚类结果，聚类中心的索引idx -> [样本集合]
        for j in range(k):  # 初始化为空列表
            clusters[j] = []
            clusters[j].append(centers[j])

        for sample in data:  # 遍历每个样本
            distances = []  # 计算该样本到每个聚类中心的距离 (只会有k个元素)
            for c in centers:  # 遍历每个聚类中心
                # 添加该样本点到聚类中心的距离
                distances.append(EMD(sample, centers[c]))
            idx = np.argmin(distances)  # 最小距离的索引
            clusters[idx].append(sample)  # 将该样本添加到第idx个聚类中心

        pre_centers = centers.copy()  # 记录之前的聚类中心点

        for c in clusters.keys():
            # 重新计算中心点（计算该聚类中心的所有样本的均值）
            centers[c] = np.mean(clusters[c], axis=0)

        is_convergent = True
        for c in centers:
            if EMD(pre_centers[c], centers[c]) > 1e-5:  # 中心点是否变化
                is_convergent = False
                break
        if is_convergent == True:
            # 如果新旧聚类中心不变，则迭代停止
            break
    return centers, clusters


def predict(p_data, centers):  # 预测新样本点所在的类
    # 计算p_data 到每个聚类中心的距离，然后返回距离最小所在的聚类。
    distances = [EMD(p_data, centers[c]) for c in centers]
    return np.argmin(distances)


TrainData=[]
TestData=[]
TestLabel=[]

if __name__ == '__main__':

    loadTrainData("D:\TNSM-revise\实验\kmeans聚类-240720\kmeans聚类\\k折交叉验证\\k5\\train-k5.csv")
    x=np.array(TrainData)
    centers,clusters=k_means(x,2)

    print(centers)

    loadTestData("D:\TNSM-revise\实验\kmeans聚类-240720\kmeans聚类\\k折交叉验证\\k5\\test-k5.csv")
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



    print("准确率",(TruePredict/TestSampleLen)*100,"%")
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

    #print("test0",TestData[0])
    #print("test1",TestData[1])
    #print(EMD(TestData[0],TestData[1]))
    #print(EMD([0.5,0.5,0,0,0,0,0,0,0,0,0],[0,0,1,0,0,0,0,0,0,0,0]))
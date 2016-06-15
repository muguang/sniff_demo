



count = 0

for i in range(1, 100000):
    if i%2 ==0 or i%3 ==0:
        count += 1
    if count == 2333:
        print("i :", i)
        break
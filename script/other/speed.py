import time
p = 1_007_621_497_415_251

start = time.time()
for i in range(p):
    print(i)
end = time.time()

print("Processing time: ", end - start)
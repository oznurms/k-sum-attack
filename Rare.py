import math
from random import randint
from ecpy.curves     import Curve,Point
from ecpy.keys       import ECPublicKey, ECPrivateKey
from ecpy.ecdsa      import ECDSA
import random
import hashlib
import array as arr 
import math



#y^2=x^3+3 over Z_101;G=(1,2) generator , <G> is the subgroup of order 17

def double(x, y, a, p):
    lambd = (((3 * x**2) % p ) *  pow(2 * y, -1, p)) % p
    newx = (lambd**2 - 2 * x) % p
    newy = (-lambd * newx + lambd * x - y) % p
    return (newx, newy)

def add_points(P, Q, p):
    xp, yp = P
    xq, yq = Q
    a=0
    if xq == yq == None:
        return xp, yp
    if xp == yp == None:
        return xq, yq
    
    assert (xq**3 + 3) % p == (yq ** 2) % p, "q not on curve"
    assert (xp**3 + 3) % p == (yp ** 2) % p, "p not on curve"
    
    if xq == xp and yq == yp:
        return double(xq, yq, a, p)
    elif xq == xp:
        return None, None
    
    lambd = ((yq - yp) * pow((xq - xp), -1, p) ) % p
    xr = (lambd**2 - xp - xq) % p
    yr = (lambd*(xp - xr) - yp) % p
    return xr, yr


def apply_double_and_add_method(G, k, p):
    target_point = G
   
    k_binary = bin(k)[2:] 
    for i in range(1, len(k_binary)):
        current_bit = k_binary[i: i+1]
        target_point = add_points(target_point, target_point, p)
        if current_bit == "1":
            target_point = add_points(target_point, G, p)
    return target_point

def find_hash(n):
    m = str.encode(str(n))
    hash_value = hashlib.sha256(m).digest()
    # Convert the hash value to an integer
    c=int.from_bytes(hash_value, 'big')
    return c

G=(1,2)

def key_gen(d):
    D=apply_double_and_add_method(G,d,101)
    return D
#keys 
da=1                       #secret key of Alice
D_a=key_gen(da)
db=3                       #secret key of Bob
D_b=key_gen(db)
dc=2                       #secret key of Carol
D_c=key_gen(dc)                



D=apply_double_and_add_method(G,(da+db+dc)%17,101)                             #With out loss og generality secret key is the sum of secret key shares
print('Agg public key',D)





m = [] 

for _ in range(2):
   random_integer = random.randint(1, 101)  
   m.append(random_integer)
print('Messages m1,m2 ',m)


sampleRa=[]
sampleRb=[]
ra=[]
rb=[]
for i in range(2): 
    ra.append(random.randint(1, 101))               #secret nonce share of Alice
    sampleRa.append(apply_double_and_add_method(G,ra[i],101) )
    rb.append(random.randint(1, 101) )               #secret nonce share of Bob
    sampleRb.append(apply_double_and_add_method(G,rb[i],101) )

print('Alice\'s public and private nonce shares',sampleRa,ra)
print('Bob\'s  public and private nonce shares',sampleRb,rb)


Rc=(1,2)                                              #random nonce value of Carol
rc=1
print('Carol\' random nonce share',Rc)

m_prime=1                                              # evil message

k=add_points(sampleRa[0],sampleRb[0],101)
R_agg=add_points(add_points(add_points(k ,sampleRa[1],101),sampleRb[1],101),Rc,101)
print('R_prime',R_agg)


e_prime=find_hash(int(bin(R_agg[0])[2:]+bin(D[0])[2:]+bin(m_prime)[2:],2)) %101                                  #evil challenge
print('e_prime',e_prime)


lambd=9

#Wagner's algorithm to find x1,x2 for k=2 case
X=[]
for i in range(lambd):  
    X.append(apply_double_and_add_method(G,random.randint(0,16),101) )
Y=[]
for i in range(lambd):  
   Y.append(apply_double_and_add_method(G,random.randint(0,16),101) )
#Lists
hashX=[]
for i in range(lambd):

    hashX.append(find_hash(int(bin(X[i][0])[2:]+bin(D[0])[2:]+bin(m[0])[2:],2)))

hashY=[]
for i in range(lambd):
    hashY.append(find_hash(int(bin(Y[i][0])[2:]+bin(D[0])[2:]+bin(m[1])[2:],2)))



for i in range(lambd):
    for j in range(lambd):
        if (hashX[i]+hashY[j]-e_prime)% 17 == 0:                      #Wagner algorithm
            e1=hashX[i]
            e2=hashY[j]    




sa1=ra[0]+(e1%17)*da                #Alice computes her signature share for each signing session
sa2=ra[1]+(e2%17)*da

sb1=rb[0]+(e1%17)*db                #Bob computes her signature share for each signing session
sb2=rb[1]+(e2%17)*db

s_prime=(sa1+sa2+sb1+sb2+rc+(e_prime*dc)) %17
print('sa',sa1,sa2)
print('sb',sb1,sb2)
print('s_prime', s_prime)

       


E=apply_double_and_add_method(D,e_prime%101,101)
print('e_prime D',E)  

Sum=add_points(R_agg,E,101)
print('R_prime+e_primeD',Sum)


        
print('Signature',R_agg[0], s_prime)
    
S_prime=apply_double_and_add_method(G,(s_prime%101),101)                                            #S'=s'G
    
print('S_prime',S_prime)   
           
        
if Sum == S_prime:                                                                        
    print('Forged signature is valid')





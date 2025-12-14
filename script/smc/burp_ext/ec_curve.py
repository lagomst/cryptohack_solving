import random

def factor_out_two_powers(n : int):
    """Factor out powers of two from n.

    Returns (q, exp) such that n == q * 2**exp and q is odd.
    """
    if n < 0 or not isinstance(n, int):
        raise ValueError("Value must be a positive integer!")
    
    q: int = n
    exp: int = 0
    # n = q * 2^exp where q must be odd integer
    while(q > 1 and q & 1 == 0): 
        exp += 1
        q = q >> 1
    return q, exp

def tonelli_shanks(p: int, n: int):
    # Solve x^2 = n mod p using Tonelli-Shanks algorithm
    # p must be an odd prime; returns one square root or None
    # if no solution.
    print(f"Tonelli shanks: {p=} {n=}")
    q, s = factor_out_two_powers(p-1)
    z = None
    for i in range(2, p):
        if pow(i, (p-1)//2, p) == p-1:
            z = i
            break
    if not z:
        return None
    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q+1)//2, p)
    while(True):
        if t == 0:
            return 0
        if t == 1:
            return r
        
        step = None
        for i in range(1, m):
            temp = pow(t, 1 << i, p)
            if temp == 1:
                step = i
                break    
        if not step:
            return None
        b_pow = 1 << (m - step - 1)
        b = pow(c, b_pow, p)
        m = step
        c = (b * b) % p
        t = (t * c) % p
        r = (r * b) % p
        
    return r

class EC:
    # Elliptic curve funciton class, 
    # represented as y^2 = x^3 + ax + b 
    def __init__(self, p: int, a: int, b: int, set_order: int=None):
        self.p = p
        self.a = a
        self.b = b
        self.set_order = set_order

    @property
    def order(self)->int:
        return self.set_order
    
    def __eq__(self, value):
        # Compare two curves by coefficients a and b
        if not isinstance(value, self.__class__):
            raise NotImplemented("unsupported operand type(s) for ==: '{}' and '{}'").format(self.__class__, type(value))
        return self.a == value.a and self.b == value.b and self.p == value.p
    
    def func(self) -> str:
        # Human readable curve equation
        return f"y^2=x^3+{self.a}*x+{self.b}"
    
    def negative(self, a: int) -> int:
        return (self.p - a) % self.p

    def inverse_modulo(self, a: int) -> int:
        return pow(a, -1, self.p)
    
    def left_term(self, y:int):
        return (y*y)%self.p
    
    def right_term(self, x:int):
        return (x*x*x + self.a*x + self.b)%self.p
    
    
    def random_point(self):
        """
        Return a random affine point based on x with x = randint(1,p-1)
        """    
        p = self.p
        while(True):
            x = random.randint(1, p-1)
            y_squared = self.right_term(x)
            if pow(y_squared, (p-1)//2, p) != 1: # Does right-term value have square-root?
                continue

            if p % 4 == 3:
                y = pow(y_squared, (p+1)//4, p)
            else:
                y = tonelli_shanks(p, y_squared) # algorithm to solve for square-root
            break

        return x, y
    
        
class PointEC:
    # Represent a point on a certain elliptic curve,
    # store as projective coordinate
    def __init__(self, curve: EC, x: int, y: int, z:int=1):
        self.curve = curve
        self.x = x % curve.p
        self.y = y % curve.p
        self.z = z
    
    def is_infinity(self):
        return self.z == 0
        
    def on_curve(self) -> bool:
        curve = self.curve
        x, y = self.get_affine_coordinate()
        return curve.left_term(y) == curve.right_term(x)
    
    def get_affine_coordinate(self):
        # WARNING: currently return None when z==0
        if self.is_infinity():
            return None, None
        
        p = self.curve.p
        inverse_z = pow(self.z, -1, p)
        x = (self.x*inverse_z)%p
        y = (self.y*inverse_z)%p
        return x, y
    
    def get_projective_coordinate(self):
        if self.is_infinity():
            return 0, 1, 0
        return self.x, self.y, self.z
    
    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplemented("unsupported operand type(s) for ==: '{}' and '{}'").format(self.__class__, type(other))
        if self.curve != other.curve:
            raise ValueError("Comparing two points belonging to different curve contexts")
        
        if self.is_infinity():
            return other.is_infinity()
        if other.is_infinity():
            return False # self.is_infinity() is False
        
        return self.get_affine_coordinate() == other.get_affine_coordinate()

    def double_projective(self):
        if self.is_infinity():
            return PointEC(self.curve,0,1,0)
        
        x1, y1, z1 = self.get_projective_coordinate()
        # Double reference from this site: https://hackmd.io/@cailynyongyong/HkuoMtz6o
        p = self.curve.p
        a = self.curve.a
        w = (a*z1*z1 + 3*x1*x1)%p
        s = (y1*z1)%p
        B = (x1*y1*s)%p
        h= (w*w - 8*B)%p
        
        x = (2*h*s)%p
        y = (w*(4*B-h) - 8*s*s*y1*y1)%p
        z = (8*pow(s,3,p))%p
        
        return PointEC(self.curve,x,y,z)
    
    def random_point(self):
        # Return a random point on finite field of generator G        
        n = self.curve.order
        k = random.randint(1, n-1)
        return k * self
    
    # Overloading add operators (+) helps us type A + B much easier
    def __add__(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplemented("unsupported operand type(s): '{}' and '{}'").format(self.__class__, type(other))
        if self.curve != other.curve:
            raise ValueError("Performing operator on two points belonging to different curve contexts")
        
        if self.is_infinity():
            return other
        if other.is_infinity():
            return self
        
        curve = self.curve
        p = curve.p
        
        x1, y1, z1 = self.get_projective_coordinate()
        x2, y2, z2 = other.get_projective_coordinate()
        # Addition reference from this site: https://hackmd.io/@cailynyongyong/HkuoMtz6o
        u = (y2*z1 - y1*z2)%p
        v = (x2*z1 - x1*z2)%p
        if v==0:
            if u != 0:
                return PointEC(curve,0,1,0)
            return self.double_projective()
        
        z3 = (pow(v,3,p)*z1*z2)%p
        if z3 == 0:
            return PointEC(curve,0,1,0)
        
        A = (u*u*z1*z2 - pow(v,3,p)-2*v*v*x1*z2)%p
        
        x3 = (v*A)%p
        y3 = (u*(v*v*x1*z2-A)-pow(v,3,p)*y1*z2)%p
        
        return PointEC(curve,x3,y3,z3)
        
    def __radd__(self, other):
        return self.__add__(other)
    
    def __iadd__(self, other):
        return self + other
    
    def __mul__(self, k):
        if not isinstance(k, int):
            raise ValueError("Multiplication only works for a PointEC and a integer or another PointEC")
        
        curve = self.curve
        if (k == 0):
            return PointEC(curve,0,1,0)
        if (k < 0):
            return (-self) * (-k)
        
        q = PointEC(curve, self.x, self.y, self.z)
        r = PointEC(curve, 0, 1, 0)
        while k > 0:
            if k%2 == 1:
                r = r + q
            q += q
            k //= 2
        # print(f"PointEC mul = {r}")
        if r.is_infinity():
            return PointEC(self.curve,0,1,0)
        return r
    
    def __imul__(self, p:int):
        return self * p

    def __rmul__(self, p:int):
        return self * p
    
    def __neg__(self):
        if self.is_infinity():
            return PointEC(self.curve, 0, 1, 0)
        p = self.curve.p
        x = self.x
        y = (-self.y)%p
        z = self.z
        return PointEC(self.curve,x,y,z)
    
    def __sub__(self, other):
        if not isinstance(other, self.__class__):
            raise NotImplementedError("unsupported operand type(s): '{}' and '{}'".format(self.__class__, type(other)))
        return self + (-other)
    
    def __isub__(self, other):
        return self - other
    
    def __rsub__(self,other):
        return other - self
    
    def __pow__(self, other:int, modulo:int=None):
        if modulo and modulo != self.curve.p:
            raise ValueError("Modulo does not match with interal curve's modulo")
        if not isinstance(other, int):
            raise ValueError("Powers on PointEC can only be called with integer!")
        if other < 0:
            return (-self) * (-other)
        return self * other
    
    def __mod__(self, other:int):
        # TODO: figure out what to do with this
        return self
    
    def __str__(self):
        t = (self.x, self.y, self.z)
        return str(t)
    
    def __repr__(self):
        return repr(self.get_affine_coordinate())
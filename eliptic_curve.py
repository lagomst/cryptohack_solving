def point_negation():
    n=9739
    a=497
    b=1768
    def y_squared(x):
        return (x**3 + b*x + a ) % n
    def negative(x):
        return (-x)%n
    x=8045
    y=6936
    # the line from P and -P never cut through esclipe again
    return negative(y)

class EC:
    def __init__(self, n:int, a:int, b:int):
        self.n = n
        self.a=a
        self.b=b
    
    def left_term(self,y:int):
        return y**2%self.n
    
    def right_term(self,x:int):
        return (x**3+self.a*x+self.b)%self.n 
    
    def is_on_curve(self,x:int, y:int):
        return y**2%self.n  == (x**3+self.a*x+self.b)%self.n 
    

def point_addition():
    n=9739
    a=497
    b=1768
    def y_squared(x):
        return (x**3 + b*x + a ) % n
    def negative(x):
        return (-x)%n
    x=8045
    y=6936

def main():
    return point_negation()

if __name__ == "__main__":
    print(main())
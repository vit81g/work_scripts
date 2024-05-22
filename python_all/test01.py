# классы
# основной класс
class A:
    def __init__(self, a1, a2):
        self.a1 = a1
        self.a2 = a2

    def summ(self):
        return self.a1 + self.a2


# наследование
class B(A):
    def __init__(self, a3):
        super(A, self).__init__(a3)
        self.a3 = a3

    def multyplay(self):
        return self.a1 * self.a2 * self.a3


class C(B):
    pass


# работа с классами
# создание объекта класса A
var1 = A(3, 4)

# обращение к атрибуту класса
print(var1.a1)
print(var1.a2)
print(var1.summ())

var2 = B(3)

#print(var2.multyplay())
print(var2.summ())


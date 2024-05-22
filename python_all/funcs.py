"""
Функции
Объявление с помощью def
"""
def test(a,b):
    return a + b

report = test(4,5)
print(report)

list1 = [1, 2, 1, 4, 1, 'a', 'b', 'c']

def list_test (a, b):
    #b = str(b)
    if b in a:
        # вывод элемента поиска и вывод индекса элемента поиска
        return b, a.index(b)

report = list_test(list1, 'c')
# на выходе получаем кортеж, выводим по одному элементу кортежа
print(report[0], report[1])


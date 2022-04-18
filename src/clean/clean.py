from tkinter import *
from tkinter.ttk import Progressbar
import time
import os
import json

def step():
    for i in range(5):
        root.update_idletasks()
        pb['value'] += 20
        time.sleep(1)
        txt['text']=pb['value'],'%'
def clean():
    print("cleaning")
root = Tk()
root.geometry("800x550")
root.minsize(250, 120)
root.title("Teapod Pro Cleaner")
root.iconbitmap("epiost.ico")
root.config(background='#353c3b')
root.maxsize(380, 160)


pb = Progressbar(
    root,
    orient = HORIZONTAL,
    length = 200,
    mode = 'determinate'
    )

pb.place(x=40, y=20)

txt = Label(
    root,
    text = '0%',
    bg = '#345',
    fg = '#fff'

)

txt.place(x=250 ,y=20 )

Button(
    root,
    text='Start',
    command=step
).place(x=40, y=50)

root.mainloop()
from tkinter import *
import tkinter as tk
from tkinter.ttk import *
from tkinter.filedialog import askopenfilename,asksaveasfilename
from subprocess import *
from tkinter import messagebox
from PIL import Image, ImageTk
import threading
import win32ui
import win32gui
import os
def fix_problems():
    for i in globals().items():
        if isinstance(i[1],Menu):
            i[1].config(tearoff=False)
dll_path = ""
dumpbin = os.path.split(__file__)[0]+"\\Tool\\dumpbin.exe"
root = Tk()
root.title("DllDumper")
top_menu = Menu()
file_menu = Menu()
functions_info = {}
def load_dll():
    global task
    if task and task.is_alive():
        task.join(0)
    global dll_path,functions_info,out
    functions_info.clear()
    dll = askopenfilename(filetypes=[("DLL", "*.dll"),("EXE","*.exe"),("All Files", "*.*")])
    if not dll:
        return
    info.place_forget()
    dll_path = dll
    infoout = check_output((dumpbin,dll_path,"/nologo","/headers")).decode("GBK",errors="replace").splitlines()[5:]
    entrypoint = ""
    base = 0
    end = 0
    for i in infoout:
        if "entry point" in i:
            entrypoint = int(i[:i.index("entry point")].strip(),16)
        if "image base" in i:
            base = int(i[:i.index("image base")].strip(),16)
            end = int(i[i.index("to")+3:-1].strip(),16)
    entrypoint += base 
    entrypoint = hex(entrypoint)[2:]
    out = check_output((dumpbin,dll_path,"/nologo","/exports")).decode("GBK",errors="replace").splitlines()[5:]
    for i in functions.get_children():
        functions.delete(i)
    try:
        out = out[out.index("    ordinal hint RVA      name")+2:]
        info.config(text="")
        for i in out:
            if not i:
                break
            if i[26:].startswith("[NONAME]"):
                if i[26:].startswith("[NONAME] (forwarded to"):
                    this = functions.insert("",END,values=("未命名",i[:11].strip(),i[12:16].strip(),i[49:-1]))
                    continue
                else:
                    this = functions.insert("",END,values=("未命名",i[:11].strip(),i[12:16].strip(),hex(base+int(i[17:25].strip(),16)) if i[17:25].strip() else ""))
            else:
                this = functions.insert("",END,values=(i[26:].strip(),i[:11].strip(),i[12:16].strip(),hex(base+int(i[17:25].strip(),16)) if i[17:25].strip() else ""))
            if i[17:25].strip():
                functions_info[int(i[:11].strip())] = hex(base+int(i[17:25].strip(),16))[2:].upper()
                if i[17:25].strip() == entrypoint:
                    functions.item(this,tags="EntryPoint")
        if not len(functions.get_children()):
            messagebox.showinfo("提示",f"\"{os.path.split(dll_path)[1]}\" 中没有函数")
            info.config(text=f"\"{os.path.split(dll_path)[1]}\" 中没有函数")
            info.place(relx=0.5,y=50,anchor=CENTER)
            
    except ValueError:
        messagebox.showinfo("提示",f"\"{os.path.split(dll_path)[1]}\" 中没有函数")
        info.config(text=f"\"{os.path.split(dll_path)[1]}\" 中没有函数")
        info.place(relx=0.5,y=50,anchor=CENTER)
    out = ""
def copy(content):
    text = Text()
    text.insert(END,content)
    text.tag_add(SEL,"1.0",END)
    text.event_generate("<<Cut>>")
    text.destroy()
file_menu.add_command(label="加载DLL...",command=load_dll)
out = ""
def threaded_disassembly(id=0):
    global out
    if not(dll_path):
        return messagebox.showerror("错误","请先加载DLL")
    top = Toplevel()
    top.title("反编译")
    top.geometry("1000x300")
    text = Text(top, wrap=WORD, font=("Consolas", 10))
    text.insert(1.0,"正在反编译...")
    text.pack(side=LEFT,fill=BOTH,expand=True)
    scroll = Scrollbar(top, command=text.yview, orient=VERTICAL)
    scroll.pack(side=RIGHT,fill=Y)
    text.config(yscrollcommand=scroll.set)
    text.tag_config("High",background="yellow",selectbackground="purple")
    text.tag_config("BreakPoint",foreground="red",selectforeground="white",selectbackground="red")
    top.update()
    if not out:
        out=check_output((dumpbin,dll_path,"/nologo","/disasm:WIDE")).decode("gbk")
    text.delete(1.0,END)
    move = True
    ln = 1.0
    beg = 0
    end = 0
    for i in out:
        if not i:
            break
        text.insert(float(ln),i[2:]+"\n")
        try:
            if id and not beg and functions_info[id]<=i[2:i.index(":")].lstrip('0'):
                beg = ln
            if id and beg and not end and "ret" in i:
                end = ln+1
        except KeyError:
            top.destroy()
            messagebox.showinfo("提示","函数不可被反编译（定义在外部？）")
        
        if i.endswith(": CC                                           int         3"):
            text.tag_add("BreakPoint",ln,ln+1)
        ln+=1
    if id:
        text.yview(beg)
        text.tag_add("High",beg,end)
    text.pack(fill=BOTH,expand=True)
    text.config(state=DISABLED)
    def contextmenu(event):
        menu = Menu(top, tearoff=0,bg="white",fg="black")
        menu.add_command(label="复制",command=lambda:text.event_generate("<<Copy>>"))
        menu.add_command(label="在必应上搜索...",command=lambda:os.system("explorer \"https://www.bing.com/search?q=%s\""%text.get(SEL_FIRST,SEL_LAST)))
        menu.post(event.x_root, event.y_root)
    text.bind("<Button-3>",contextmenu)
task = None
def disassembly(id=0):
    global task
    if not task or not task.is_alive():
        task = threading.Thread(target=threaded_disassembly,args=(id,))
        task.start()
file_menu.add_command(label="反编译这个DLL...",command=disassembly)
file_menu.add_command(label="反编译函数...",command=lambda:disassembly(int(functions.item(functions.selection()[0])["values"][1])))
photos = []
def extract_icon():
    photos.clear()
    if not(dll_path):
        return messagebox.showerror("错误","请先加载DLL")
    top = Toplevel()
    top.geometry("400x200")
    top.title("反编译图标")
    msg = Label(top,text="正在反编译...")
    msg.pack(fill=X)
    progress = Progressbar(top)
    progress.pack(fill=X)
    top.update()
    try:
        for i in os.listdir("Icons"):
            os.remove(f"Icons\\{i}")
    except:
        os.makedirs("Icons")
    try:
        iconcount = win32gui.ExtractIcon(root.winfo_id(), dll_path, -1)
        large, small = win32gui.ExtractIconEx(dll_path, 0, iconcount)
    except Exception as e:
        top.destroy()
        messagebox.showerror("错误",e.args[-1])
        return
    i = 0
    progress.config(maximum=len(large)+1)
    for ico in large:
        hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
        hbmp = win32ui.CreateBitmap()
        hbmp.CreateCompatibleBitmap(hdc, 32, 32)
        hdc = hdc.CreateCompatibleDC()
        hdc.SelectObject(hbmp)
        win32gui.FillRect(hdc.GetHandleAttrib(), (0,0,32,32), win32gui.CreateSolidBrush(0xffffff))
        hdc.DrawIcon((0,0), ico)
        hbmp.SaveBitmapFile(hdc, f"Icons\\{i}_32.bmp")
        i+=1
        progress.step()
        top.update()
        win32gui.DestroyIcon(ico)
    for ico in small:
        win32gui.DestroyIcon(ico)
    text = Text(top,borderwidth=0,width=0)
    for i in os.listdir("Icons"):
        if i.endswith("_32.bmp"):
            simg = Image.open("Icons\\"+i)
            img = ImageTk.PhotoImage(simg)
            photos.append(img)
            button = tk.Button(top,image=img,relief=FLAT,background="white",activebackground="white",borderwidth=0,
                               highlightthickness=0, 
command=lambda: simg.save(asksaveasfilename(defaultextension=".bmp",filetypes=[("BMP",".bmp"),("JPG",".jpg"),("PNG", ".png")],parent=top)))
            text.window_create(END, window=button,padx=5,pady=5)
            progress.step()
    text.config(state=DISABLED,selectbackground="white")
    msg.destroy()
    progress.destroy()
    text.pack(fill=BOTH,expand=True,side=LEFT)
    scroll = Scrollbar(top, command=text.yview, orient=VERTICAL)
    scroll.pack(side=RIGHT,fill=Y)
    text.config(yscrollcommand=scroll.set)
file_menu.add_command(label="反编译图标...",command=extract_icon)
top_menu.add_cascade(label="文件", menu=file_menu)
edit_menu = Menu()
edit_menu.add_command(label="复制函数名称",command=lambda:copy(functions.item(functions.selection()[0])["values"][0]))
edit_menu.add_command(label="复制函数位置",command=lambda:copy(functions.item(functions.selection()[0])["values"][3]))
edit_menu.add_command(label="在必应上搜素...",command=lambda:os.system("explorer \"https://www.bing.com/search?q=%s\""%functions.item(functions.selection()[0])["values"][0]))
top_menu.add_cascade(label="编辑", menu=edit_menu)
root.config(menu=top_menu, bg="white")
def contextmenu_functions(event):
    menu = Menu(tearoff=False)
    menu.add_command(label="反编译函数...",command=lambda:disassembly(int(functions.item(functions.selection()[0])["values"][1])))
    menu.add_command(label="复制函数名称",command=lambda:copy(functions.item(functions.selection()[0])["values"][0]))
    menu.add_command(label="复制函数位置",command=lambda:copy(functions.item(functions.selection()[0])["values"][3]))
    menu.add_command(label="在必应上搜素...",command=lambda:os.system("explorer \"https://www.bing.com/search?q=%s\""%functions.item(functions.selection()[0])["values"][0]))
    menu.post(event.x_root,event.y_root)
functions = Treeview(root, columns=["名称", "顺序", "提示号","函数位置"],show="headings",selectmode="browse")
def sortby(tree:Treeview, col, key=lambda x:x):
    lst = [(tree.set(st,col),st) for st in tree.get_children("")]
    lst.sort(key=lambda x:key(x[0]))
    for index, item in enumerate(lst):
        tree.move(item[1],"",index)      
functions.heading("名称", text="名称", anchor=CENTER, command=lambda:sortby(functions,"名称"))
functions.heading("顺序", text="顺序", anchor=CENTER,command=lambda:sortby(functions,"顺序",lambda x:int(x)))
functions.heading("提示号", text="提示号", anchor=CENTER,command=lambda:sortby(functions,"提示号",lambda x:int(x,16)))
functions.heading("函数位置", text="函数位置", anchor=CENTER,command=lambda:sortby(functions,"函数位置"))
functions.column("名称", width=300, anchor=W, stretch=True,minwidth=300,)
functions.column("顺序", width=100, anchor=W, stretch=True,minwidth=100,)
functions.column("提示号", width=100, anchor=W, stretch=True,minwidth=100,)
functions.column("函数位置", width=100, anchor=W, stretch=True,minwidth=100,)
functions.pack(side=LEFT,fill=BOTH,expand=True)
functions.tag_configure("EntryPoint",foreground="blue")
info = Label(functions,text="请点击【文件】->【加载DLL...】加载一个DLL",background="white",foreground="grey")
info.place(relx=0.5,y=50,anchor=CENTER)
scroll = Scrollbar(root, command=functions.yview, orient=VERTICAL)
functions.config(yscrollcommand=scroll.set)
functions.bind("<Button-3>",contextmenu_functions)
def set_show_or_hide():
    if scroll.get()[0] == 0.0 and scroll.get()[1] == 1.0:
        scroll.forget()
    else:
        scroll.pack(side=RIGHT,fill=Y)
    root.after(1,set_show_or_hide)

fix_problems()
root.after(1,set_show_or_hide)
root.mainloop()

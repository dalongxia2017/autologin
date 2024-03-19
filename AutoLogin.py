import tkinter
from tkinter import messagebox
from bs4 import BeautifulSoup
from scapy.all import *
import requests
import winreg
import threading
import pystray
from PIL import Image
from pystray import MenuItem

# region 代码部分

# region 初始变量

passwd = ""
filepath= sys.argv[0]

# endregion

# region 登录部分

# 读取密码
def get_passwd_file():
    global passwd
    try:
        with open("passwd.txt") as f:
            passwd = f.readlines()[0]
    except Exception:
        pass

# 检测状态
def check_status_func():
    try:
        req = requests.get(url="http://1.1.1.3:90/login")
        req.encoding = "utf-8"
        soup = BeautifulSoup(req.text, 'lxml')
        status = soup.select('#div_login > h1 > span:nth-child(2)')
        if (status[0].get_text() == "您已经成功登录!"):
            return 1
        else:
            return 0
    except Exception:
        return 0

def check_status():
    if (check_status_func()):
        status_str.set("已登录")
        status_label.config(fg="green")
    else:
        status_str.set("未登录")
        status_label.config(fg="red")
    get_autostart()

# 登录
def login():
    get_passwd_file()
    http_post(passwd)
    check_status()

# 登出
def logout():
    http_post("login_type=logout&page_language=zh")
    check_status()

# 重登
def relogin():
    get_passwd_file()
    http_post("login_type=logout&page_language=zh")
    http_post(passwd)
    check_status()

# 模拟请求
def http_post(data):
    url = "http://1.1.1.3:90/login"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Referer': 'http://1.1.1.3:90/login'
    }

    data_encoded = data.encode('utf-8')
    
    response = requests.post(url, data_encoded, headers, timeout=20)
    
    if response.status_code == 200:
        return response.text
    else:
        return f"Error: {response.status_code}"

# endregion

# region 自动抓包

cat_passwd = ""
stop_cat_pack = 0

def packet_callback(packet):
    global cat_passwd,stop_cat_pack
    if not (stop_cat_pack):
        if packet.haslayer(TCP):
            if packet[TCP].dport == 90:
                if packet.haslayer(Raw):
                    load = packet[Raw].load.decode('utf-8', errors='ignore')
                    if "POST" in load:
                        list = load.split('\n')
                        for line in list:
                            if ('username' in line):
                                cat_passwd = line
                                return 1
    else:
        stop_cat_pack = 0
        return 1

cat_pack_run = 1

def cat_pack():
    global cat_pack_run,cat_thread,stop_cat_pack
    if (cat_pack_run):
        if not (messagebox.askyesno("警告！","抓包会退出登录，请确认是否有不可断网的程序正在运行，是否继续抓包？")):
            pass
        cat_pack_button.config(text="停止抓包")
        cat_pack_run = 0
        logout()
        os_url_explore("http://1.1.1.3:90/login")
        cat_thread = threading.Thread(target=cat_pack_thread)
        cat_thread.start()
    else:
        cat_pack_button.config(text="一键抓包")
        cat_pack_run = 1
        stop_cat_pack = 1

def cat_pack_thread():
    global cat_pack_run
    sniff(stop_filter=packet_callback)
    if (messagebox.askokcancel("结果","是否写入passwd，你的passwd为：" + cat_passwd)):
        f = open("passwd.txt","w")
        f.write(cat_passwd)
        f.close()

    cat_pack_button.config(text="一键抓包")
    cat_pack_run = 1


def os_url_explore(url):
    import platform
    import subprocess

    if platform.system().lower() == "windows":
        cmd = "start " + url
    else:
        cmd = "open " + url
    subprocess.run(cmd, shell=True)

def open_login_web(self):
    os_url_explore("http://1.1.1.3:90/login")

# endregion
                                   
# region 自动启动
def autostart():
    if (isautostart.get()):
        set_autostart()
    else:
        del_autostart()
    
def get_autostart():
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    value_name = "autologin_cshrimp"

    global isautostart

    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
        value, value_type = winreg.QueryValueEx(key, value_name)
        winreg.CloseKey(key)
        if not value is None:
            isautostart.set("1")
            set_autostart()
        else:
            isautostart.set("0")
            del_autostart()
    except Exception:
        pass

def set_autostart():
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    value_name = "autologin_cshrimp"

    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, filepath)
        winreg.CloseKey(key)
    except Exception:
        pass

def del_autostart():
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    value_name = "autologin_cshrimp"

    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
        winreg.DeleteValue(key, value_name)
        winreg.CloseKey(key)
    except Exception:
        pass

# endregion

# region 自动登录

stop_login = 0

def load_autologin():
    if (os.path.exists("autologin")):
        isautologin.set("1")
    else:
        isautologin.set("0")
    autologin()

def autologin():
    global stop_login
    login_thread = threading.Thread(target=autologin_thread)   
    if (isautologin.get()):
        stop_login = 0
        f = open("autologin",'w')
        f.close
        login_thread.start()
    else:
        stop_login = 1
        try:
            os.remove("autologin")
        except Exception:
            pass

def autologin_thread():
    while True:
        if (stop_login):
            break
        if (check_status_func()):
            check_status()
        else:
            login()
            check_status()
        time.sleep(1)
     
# endregion

# endregion

# region 初始化

get_passwd_file()

# endregion

# region 托盘设置

def show_window():
    main.deiconify()

def on_exit():
    icon.stop()
    main.destroy()

def hide():
    main.withdraw()

menu = (MenuItem(text='打开窗口', action=show_window,default=True),
        MenuItem(text='退出', action=on_exit)
        )
image = Image.open("ico.ico")
icon = pystray.Icon("cshrimp-autologin", image, "广信自动登录程序", menu)


# endregion

# region GUI窗体

# region 窗体属性

main = tkinter.Tk()
main.title('自动登录-python-rebuild')
main.geometry('368x130')
main.resizable(False,False)

# endregion

# region 组件属性

# 一键登陆按钮
login_button = tkinter.Button(text="登陆",font=('宋体', 20),width=8,height=1,command=login)
login_button.grid(row=0,column=0)

# 一键登出按钮
logout_button = tkinter.Button(text="登出",font=('宋体', 20),width=8,height=1,command=logout)
logout_button.grid(row=1,column=0)

# 一键重登按钮
relogin_button = tkinter.Button(text="重登",font=('宋体', 20),width=8,height=1,command=relogin)
relogin_button.grid(row=0,column=1)

# 一键抓包按钮
cat_pack_button = tkinter.Button(text="一键抓包",font=('宋体', 20),width=8,height=1,command=cat_pack)
cat_pack_button.grid(row=1,column=2)

# 刷新状态
get_status_button = tkinter.Button(text="刷新状态",font=('宋体', 20),width=8,height=1,command=check_status)
get_status_button.grid(row=1,column=1)

# 关闭按钮
exit_button = tkinter.Button(text="退出程序",font=('宋体', 20),width=8,height=1,command=on_exit)
exit_button.grid(row=0,column=2)


# 状态提示
status_str = tkinter.StringVar()
status_label = tkinter.Label(textvariable=status_str,font=('宋体', 20))
status_label.bind("<Button-1>",open_login_web)
status_label.grid(row=2,column=2)

# 自启选项
isautostart=tkinter.IntVar()
get_autostart()
startup_box = tkinter.Checkbutton(text="自动启动",font=('宋体', 15),variable=isautostart,onvalue=1,offvalue=0,command=autostart)
startup_box.grid(row=2,column=0)

# 自登选项
isautologin=tkinter.IntVar()
auto_login_box = tkinter.Checkbutton(text="自动登陆",font=('宋体', 15),variable=isautologin,onvalue=1,offvalue=0,command=autologin)
auto_login_box.grid(row=2,column=1)

# endregion

# region 创建窗体

check_status()
load_autologin()
main.protocol('WM_DELETE_WINDOW', hide)
threading.Thread(target=icon.run, daemon=True).start()
main.mainloop()

# endregion

# endregion
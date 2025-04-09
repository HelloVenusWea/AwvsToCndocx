from flask import Flask, render_template, request
import requests
import json
import time
import os
from urllib3.exceptions import InsecureRequestWarning
from generatereport import read_json_file, parse_awvs_data, generate_report
# 在顶部添加导入
from flask import send_from_directory
import glob

# 禁用SSL证书验证警告(仅用于测试环境)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Acunetix API配置
API_URL = "https://192.168.80.128:3443/api/v1"
API_KEY = "1986ad8c0a5b3df4d7028d5f3c06e936c3335881a3abb4f228787be18adeece51"
HEADERS = {
    "X-Auth": API_KEY,
    "Content-Type": "application/json"
}

app = Flask(__name__)


def init_check():
    """检查API连接是否正常"""
    try:
        r = requests.get(API_URL + '/targets', headers=HEADERS, verify=False)
        if r.status_code == 401:
            return 'AWVS认证失败，请检查API_KEY是否正确'
        if r.status_code == 200:
            return 'AWVS连接成功'
    except Exception as e:
        return f'初始化失败: {str(e)}'


def read_urls_from_file(filename="url.txt"):
    """从文件读取URL列表"""
    if not os.path.exists(filename):
        return []
    with open(filename, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    return urls


def add_target(url):
    """添加扫描目标"""
    data = {
        "address": url,
        "description": "From url.txt",
        "criticality": "10"
    }
    try:
        response = requests.post(API_URL + '/targets', headers=HEADERS, json=data, verify=False)
        response.raise_for_status()
        return response.json().get('target_id')
    except Exception as e:
        return f"添加目标 {url} 失败: {str(e)}"


def start_scan(target_id, profile_id="11111111-1111-1111-1111-111111111111"):
    """启动扫描任务"""
    data = {
        "target_id": target_id,
        "profile_id": profile_id,
        "schedule": {"disable": False}
    }
    try:
        response = requests.post(API_URL + '/scans', headers=HEADERS, json=data, verify=False)
        response.raise_for_status()
        return response.json().get('scan_id')
    except Exception as e:
        return f"启动扫描失败: {str(e)}"


def get_scan_status():
    """获取扫描状态和详细信息"""
    try:
        response = requests.get(API_URL + '/scans', headers=HEADERS, verify=False)
        response.raise_for_status()
        scans = response.json().get('scans', [])
        scan_details = []
        for scan in scans:
            target = scan.get('target', {})
            current_session = scan.get('current_session', {})
            details = {
                'Target': target.get('address', '未知地址'),
                'Target Description': target.get('description', '无描述'),
                'Scan Profile': scan.get('profile_id', '未知配置'),
                'Schedule': current_session.get('schedule', {}).get('next_run', '无计划'),
                'Vulnerabilities': current_session.get('severity_counts', {}),
                'Status': current_session.get('status', '未知状态')
            }
            scan_details.append(details)
        return scan_details
    except Exception as e:
        return f"获取扫描状态失败: {str(e)}"


def get_scans():
    """获取所有扫描任务"""
    try:
        response = requests.get(API_URL + '/scans', headers=HEADERS, verify=False)
        response.raise_for_status()
        scans = response.json().get('scans', [])
        for scan in scans:
            if 'current_session' in scan and 'status' in scan['current_session']:
                scan['status'] = scan['current_session']['status']
            else:
                scan['status'] = 'unknown'
        return scans
    except Exception as e:
        return []


def export_report(scan_id):
    """
    导出扫描报告(JSON格式)
    Args:
        scan_id (str): 要导出的扫描任务ID
    Returns:
        str: 报告导出任务ID
    """
    data = {
        "export_id": "21111111-1111-1111-1111-111111111130",  # 固定导出ID
        "source": {
            "list_type": "scans",
            "id_list": [scan_id]
        }
    }
    try:
        response = requests.post(API_URL + '/exports', headers=HEADERS, json=data, verify=False)
        response.raise_for_status()
        export_task = response.json()
        return f"导出任务已创建，报告ID: {export_task['report_id']}"
    except Exception as e:
        return f"创建导出任务失败: {str(e)}"


@app.route('/download_awvs_report')
def download_awvs_report(report_id, save_dir="reports"):
    """下载AWVS扫描报告(JSON格式)"""
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)
    
    try:
        max_retries = 5  # 增加重试次数
        retry_count = 0
        wait_time = 2  # 初始等待时间
        
        while retry_count < max_retries:
            try:
                # 检查导出状态
                status_response = requests.get(
                    API_URL + f'/exports/{report_id}', 
                    headers=HEADERS, 
                    verify=False,
                    timeout=30  # 添加超时
                )
                
                if status_response.status_code != 200:
                    print(f"状态检查失败，HTTP状态码: {status_response.status_code}")
                    retry_count += 1
                    time.sleep(wait_time)
                    wait_time *= 2  # 指数退避
                    continue
                
                status_data = status_response.json()
                status = status_data.get('status')
                
                if status == 'completed':
                    download_urls = status_data.get('download', [])
                    if not download_urls:
                        print("报告生成完成但未返回下载链接")
                        return "报告生成完成但未返回下载链接"
                    
                    download_url = download_urls[0]
                    full_url = API_URL.replace("api/v1", "") + download_url
                    
                    # 下载报告
                    report_response = requests.get(
                        full_url,
                        headers=HEADERS,
                        verify=False,
                        timeout=60  # 增加下载超时
                    )
                    
                    if report_response.status_code != 200:
                        print(f"下载失败，HTTP状态码: {report_response.status_code}")
                        retry_count += 1
                        time.sleep(wait_time)
                        continue
                    
                    # 保存报告
                    filename = f"{save_dir}/report_{int(time.time())}.json"
                    with open(filename, 'wb') as f:
                        f.write(report_response.content)
                    
                    # 生成Word报告
                    try:
                        report_data = read_json_file(filename)
                        targets, vulns = parse_awvs_data(report_data)
                        generate_report(targets, vulns)
                        return f"报告已成功生成并保存到: {filename}"
                    except Exception as e:
                        print(f"生成Word报告时出错: {str(e)}")
                        return f"JSON报告已保存，但生成Word报告失败: {str(e)}"
                
                elif status in ('failed', 'cancelled'):
                    print(f"报告生成失败，状态: {status}")
                    return f"报告生成失败，状态: {status}"
                
                # 报告仍在生成中
                print(f"报告生成中，当前状态: {status}, 等待{wait_time}秒后重试...")
                time.sleep(wait_time)
                retry_count += 1
                wait_time = min(wait_time * 2, 30)  # 指数退避，最大等待30秒
            
            except requests.exceptions.RequestException as e:
                print(f"请求出错: {str(e)}")
                retry_count += 1
                time.sleep(wait_time)
                wait_time = min(wait_time * 2, 30)
            except Exception as e:
                print(f"未知错误: {str(e)}")
                retry_count += 1
                time.sleep(wait_time)
        
        return "达到最大重试次数，下载报告失败。最后状态: " + status if 'status' in locals() else "无法获取状态"
    
    except Exception as e:
        print(f"下载报告过程中发生异常: {str(e)}")
        return f"下载报告失败: {str(e)}"


def start_scan_from_urls():
    result = init_check()
    if "失败" in result:
        return result
    urls_input = request.form.get('urls')  # 确保这里能正确获取到表单数据
    if not urls_input:
        return "没有输入可扫描的URL"
    urls = [url.strip() for url in urls_input.splitlines() if url.strip()]
    output = []
    for url in urls:
        output.append(f"正在处理: {url}")
        target_id = add_target(url)
        if isinstance(target_id, str) and "失败" in target_id:
            output.append(target_id)
            continue
        scan_id = start_scan(target_id)
        if isinstance(scan_id, str) and "失败" in scan_id:
            output.append(scan_id)
        else:
            output.append(f"扫描已启动，扫描ID: {scan_id}")
    return "<br>".join(output)


def export_and_download_reports():
    output = ["开始导出报告..."]
    scans = get_scans()
    
    if not scans:
        return "没有找到任何扫描任务"
    
    for scan in scans:
        if scan.get('status') != 'completed':
            output.append(f"跳过未完成的扫描: {scan.get('target', {}).get('address', '未知地址')} (状态: {scan.get('status', '未知')})")
            continue
            
        try:
            output.append(f"处理扫描: {scan.get('target', {}).get('address', '未知地址')}")
            
            # 导出报告
            export_result = export_report(scan['scan_id'])
            output.append(export_result)
            
            if "创建导出任务失败" in export_result:
                continue
                
            # 提取报告ID
            try:
                report_id = export_result.split(": ")[1].strip()
            except Exception as e:
                output.append(f"提取报告ID失败: {str(e)}")
                continue
                
            # 下载报告
            download_result = download_awvs_report(report_id)
            output.append(download_result)
            
            # 检查是否下载成功
            if "失败" in download_result:
                output.append("警告: 报告下载失败")
            
        except Exception as e:
            output.append(f"处理扫描时出错: {str(e)}")
            continue
    
    return "<br>".join(output)

# 保留新增的DOCX下载路由
@app.route('/download_report')
def download_docx_report():
    """下载DOCX报告文件"""
    filename = request.args.get('filename')
    if not filename or not os.path.exists(filename):
        return "文件不存在", 404
    return send_from_directory(
        directory=os.path.dirname(filename),
        path=os.path.basename(filename),
        as_attachment=True
    )


def delete_completed_scans():
    output = []
    scans = get_scans()
    for scan in scans:
        if scan.get('status') == 'completed':
            scan_id = scan['scan_id']
            try:
                response = requests.delete(API_URL + f'/scans/{scan_id}', headers=HEADERS, verify=False)
                response.raise_for_status()
                output.append(f"扫描任务 {scan_id} 已删除")
            except Exception as e:
                output.append(f"删除扫描任务 {scan_id} 失败: {str(e)}")
    if not output:
        return "没有已完成的扫描任务可删除"
    return "<br>".join(output)


# 在顶部添加导入
from flask import redirect, url_for, session, flash
from functools import wraps

# 添加配置
app.secret_key = 'your-secret-key-here'  # 请替换为强密钥
LOGIN_USERNAME = 'admin'  # 预设用户名
LOGIN_PASSWORD = 'admin123'  # 预设密码

# 添加登录检查装饰器
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 添加登录路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == LOGIN_USERNAME and password == LOGIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        flash('用户名或密码错误')
    return render_template('login.html')

# 添加登出路由
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    result = ""
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'check_status':
            result = get_scan_status()
        elif action == 'confirm_start_scan':
            result = start_scan_from_urls()
        elif action == 'export_download':
            result = export_and_download_reports()
        elif action == 'delete_completed':
            result = delete_completed_scans()
    
    # 获取报告列表
    if not os.path.exists('CNResult'):
        os.makedirs('CNResult')
    reports = [f.replace('\\', '/') for f in glob.glob('CNResult/*.docx')]
    
    return render_template('index.html', result=result, reports=reports)


@app.route('/report_management')
@login_required
def report_management():
    """报告管理页面"""
    if not os.path.exists('CNResult'):
        os.makedirs('CNResult')
    reports = [f.replace('\\', '/') for f in glob.glob('CNResult/*.docx')]
    return render_template('report_management.html', reports=reports)

@app.route('/download_report')
def download_report():
    """下载报告文件"""
    filename = request.args.get('filename')
    if not filename or not os.path.exists(filename):
        return "文件不存在", 404
    return send_from_directory(
        directory=os.path.dirname(filename),
        path=os.path.basename(filename),
        as_attachment=True
    )


if __name__ == '__main__':
    # 修改运行配置，允许所有网络接口访问
    app.run(host='0.0.0.0', port=5000, debug=True)
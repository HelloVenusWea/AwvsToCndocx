import time  
import json
import sqlite3
from datetime import datetime
import base64, zlib
from wordReport import *

def getCN(string):
    conn = sqlite3.connect('trans.db')
    cur = conn.cursor()
    cur.execute('SELECT vulcn,description,recommendation FROM trans where vulen=?', (string,))
    result = cur.fetchone()
    conn.close()
    return result or (string, string, string)  # 如果没找到记录，返回原始字符串

def read_json_file(json_file):
    """
    读取 JSON 文件
    :param json_file: JSON 文件路径
    :return: 解析后的 JSON 数据
    """
    with open(json_file, 'r', encoding='utf-8') as f:
        return json.load(f)

def parse_awvs_data(report_data):
    """
    解析 AWVS JSON 报告数据
    :param report_data: 解析后的 JSON 数据
    :return: 目标信息列表和漏洞信息列表
    """
    targets_info = []
    vuln_info = []
    
    # 处理目标信息
    for scan in report_data['export']['scans']:
        target_data = scan['info']
        tmp_target = {
            '目标主机': target_data['host'],
            '目标地址': target_data['start_url'],
            '目标服务': target_data['server'],
            '目标描述': target_data['host'],
            '开始时间': datetime.datetime.strptime(target_data['start_date'].replace('Z', '+00:00'), '%Y-%m-%dT%H:%M:%S.%f%z').strftime('%Y-%m-%d %H:%M:%S'),
            '结束时间': datetime.datetime.strptime(target_data['end_date'].replace('Z', '+00:00'), '%Y-%m-%dT%H:%M:%S.%f%z').strftime('%Y-%m-%d %H:%M:%S'),
            '风险数量': {"high": 0, "medium": 0, "low": 0},
            '主机发现': target_data['hosts_discovered']
        }
        targets_info.append(tmp_target)
        
        # 处理漏洞信息
        for vuln_type in scan['vulnerability_types']:
            # 获取请求和响应数据
            request_data = ''
            response_data = ''
            
            # 检查是否有 vulnerabilities 数组
            if 'vulnerabilities' in scan and len(scan['vulnerabilities']) > 0:
                # 查找当前漏洞类型对应的漏洞项
                for vuln in scan['vulnerabilities']:
                    if vuln["info"]['vt_id'] == vuln_type['vt_id']:
                        request_data = vuln["info"]['request']
                        try:
                            # 先进行base64解码
                            decoded_data = base64.decodebytes(vuln['response'].encode())
                            
                            # Linux专用解压处理
                            try:
                                # 方法1：使用gzip模块直接解压
                                import gzip
                                with gzip.GzipFile(fileobj=BytesIO(decoded_data)) as f:
                                    response_data = f.read()
                            except Exception:
                                try:
                                    # 方法2：尝试zlib解压（带gzip头部识别）
                                    response_data = zlib.decompress(decoded_data, 16 + zlib.MAX_WBITS)
                                except zlib.error:
                                    try:
                                        # 方法3：尝试原始zlib解压
                                        response_data = zlib.decompress(decoded_data)
                                    except Exception as e:
                                        print(f"解压缩失败，使用原始数据: {str(e)}")
                                        response_data = decoded_data
                            
                            # 统一解码处理
                            response_data = response_data.decode('utf-8', 'ignore').replace('\x00', '')
                            print(request_data)
                        except Exception as e:
                            print(f"处理响应数据时出错: {str(e)}")
                            response_data = ''
                        break
            
            tmp_vuln = {
                '漏洞ID': vuln_type['vt_id'],
                '来源': 'scan',
                '漏洞细节': vuln_type.get('details_template', ''),
                '首次发现漏洞的日期': target_data['start_date'],
                '风险名称': getCN(vuln_type['name'])[0],
                '目标主机': target_data['host'],
                '请求数据': request_data,
                '响应数据': response_data,
                '目标地址': target_data['start_url'],
                '目标描述': target_data['start_url'],
                '分类地址': target_data['start_url'],
                '危险分类': target_data['start_url'],
                '影响': vuln_type['impact'],
                '风险描述': getCN(vuln_type['name'])[1],
                '修复建议': getCN(vuln_type['name'])[2],
                '风险标签': ', '.join(vuln_type['tags']),
                'cvss评分': vuln_type['cvss_score'],
                '参考': vuln_type['refs'],
                '风险类型': vuln_type['type'],
                '风险级别': '高' if vuln_type['severity'] >= 3 else '中' if vuln_type['severity'] == 2 else '低'
            }
            vuln_info.append(tmp_vuln)
    
    # 风险计数
    def targets_severity_counts(targets_info, vuln_info):
        for targets in targets_info:
            for vuln in vuln_info:
                if vuln['危险分类'] == targets['目标地址']:
                    if vuln['风险级别'] == '高':
                        targets['风险数量']['high'] += 1
                    if vuln['风险级别'] == '中':
                        targets['风险数量']['medium'] += 1
                    if vuln['风险级别'] == '低':
                        targets['风险数量']['low'] += 1
        return targets_info

    targets_info = targets_severity_counts(targets_info, vuln_info)
    
    return targets_info, vuln_info

def generate_report(targets, vulns):
    """
    生成报告
    :param targets: 目标信息列表
    :param vulns: 漏洞信息列表
    """
    reportWord = Report(targets, vulns, './reportDemo/reportDemo.docx', '')
    reportWord.create()

if __name__ == "__main__":
    # 读取 JSON 报告
    json_file = 'd8a28756876424ed498391520a79a33683076460ee81a2f7f3f4d7ed13099cfe43c352b267ebb48911849c1e-363c-4b0a-a9d1-b5c2f7d5b9f0.json'
    report_data = read_json_file(json_file)
    
    # 解析数据
    targets, vulns = parse_awvs_data(report_data)
    
    # 生成报告
    generate_report(targets, vulns)
    
    # 打印结果
    print(json.dumps(vulns[0], indent=2, ensure_ascii=False))
# pairwise-waf-normalize

WAF 一上线，正常表单先被误杀：请求体只按 Content-Type 选解析器，multipart 边界里的参数完全没有检查；URL 解码只做一次，双重编码的路径穿越绕过规则；Unicode 规范化在检测前没有做，全角字符和兼容字符直接漏过；同名参数取第一个，后端取最后一个，参数污染规则失效；chunked 传输没有重组，分块边界把关键字拆开；路径规范化把反斜杠当普通字符，Windows 后端解析出不同路径。security/waf_normalize.py 是核心，tests/test_waf_normalize.py 15个红。要修的是：按实际解析器取参；循环解码到稳定；Unicode NFKC；参数全集；chunk 重组；跨平台路径规范化。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。

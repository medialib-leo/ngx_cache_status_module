# cache_status

nginx http cache status in json format

## 编译

```
./configure --add-module={path}/ngx_cache_status_module
make
```

## 使用

```
location /cache_status {
    cache_status;
}
```

## 接口返回

```
{
	"start_time": 1597915737,
	"requests": 2,
	"miss": 2,
	"bypass": 0,
	"expired": 0,
	"stale": 0,
	"updating": 0,
	"revalidated": 0,
	"hit": 0,
	"scarce": 0,
	"misc": 0
}
```
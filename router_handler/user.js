// 导入数据库操作模块
 const db = require('../db/index')

// 导入 bcrypt = require('bcryptjs)
const bcrypt = require('bcryptjs')

// 导入生成TOKEN的包
const jwt = require('jsonwebtoken')
// 导入全局的配置文件
const config = require('../config')
// 注册新用户的处理函数
exports.regUser = (req,res) => {
    // 获取客户端提交到服务器的用户信息
    const userinfo = req.body
    // 对表单中的数据，进行合法性的校验
    // if(!userinfo.username || !userinfo.password) {
    //     return res.send({
    //         status:1,
    //         message: '用户名或密码不合法'
    //     })
    // }

          //定义SQL语句查询用户名是否被占用
    const sqlStr = 'select * from new_users where username=?'
    db.query( sqlStr,[userinfo.username], function (err,results) {
        // 执行SQL语句失败
        if (err) {
            return res.cc(err)
        }
        // 判断用户名是否被占用
            if ( results.length ==1 ) {
                return res.cc( '用户名被占用，请更换用户名！')
            }
            // 调用bcrypt.hashSync()
               userinfo.password =  bcrypt.hashSync(userinfo.password, 10)
            //    定义插入新用户的sql语句
            const sql = 'insert into new_users set ?'
            // 调用db.query()执行sql语句
            db.query(sql, {username:userinfo.username, password: userinfo.password}, (err,results) => {
                // 判断SQL语句是否执行成功
                if (err) return res.cc(err)
                // 判断影响
                if (results.affectedRows !== 1) return res.cc('注册用户失败，请稍后尝试')
                //    注册成功
                // res.send({ status:0, message: '注册成功！'})
                res.cc('注册成功！',0)
            })
        })


    // res.send('reguster ok')
}


// 用户登录的处理函数
exports.login = (req,res) => {
    // 接收表单的数据
    const userinfo = req.body
    // 定义sql语句
    const sql = `select * from new_users where username=?`
    // 执行sql语句，根据用户名查询用户的信息
    db.query(sql, userinfo.username, (err,results) => {
        // 执行sql语句失败
        if (err) return res.cc(err)
        // 执行SQL语句成功，但是获取到的数据条数不等于一
        if (results.length !== 1) return res.cc('登录失败！')


        // TOOD:判断密码是否正确
        const compareResult = bcrypt.compareSync(userinfo.password, results[0].password)
        if (!compareResult) return res.cc('登录失败了！！！')

        // TOOD:在服务器端生成token的字符串
        const user = {...results[0], password: '',user_pic: ''}
        // 对用户的信息进行加密，生成TOKEN的字符串
        const tokenStr = jwt.sign(user,config.jwtSecretKey, {expiresIn: config.expiresIn})
        const token = 'Bearer '+ tokenStr
        // 调用res.send()将Token响应给客户端
        res.send({
            status:0,
            message: '登录成功！',
            token:  token,

        })
    
        
    })
}
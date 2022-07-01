// 文章的处理函数模块
const path = require('path')
const db = require('../db/index')



// 导入需要的处理函数模块
exports.addArticle = (req,res) => {
    console.log(req.file);
    if (!req.file || req.file.fieldname !== 'cover_img') return res.cc('文章封面是必选项')


    // 处理文章信息对象
    const articleInfo = {
        ...req.body,
        cover_img: path.join('/uploads', req.file.filename),
        pub_date: new Date(),
        author_id: req.user.id,
    }
    

    const sql = `insert into ev_articles set ?`
    db.query(sql, articleInfo ,(err,results) => {
        if (err) return res.cc(err)
        if ( results.affectedRows !==1) return res.cc('发布文章失败！')
        res.cc('发布文章成功！', 0)
    })
    
    
    
}
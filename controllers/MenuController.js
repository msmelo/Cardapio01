'use strict';

const Category = require('../models/CategoryModel.js');
const qrCode = require('qr-image');
const fs = require('fs');
const path = require('path');
const htmlPDF = require('html-pdf');
const handlebars = require('handlebars');


module.exports = {

  findCategoriesByCompany: (req, res, next) =>{
    const companyID = req.query.companyID; //Parâmetro passado via GET

    //Buscar todas categorias associadas a companhia desejada
    // Retorna apenas o nome e o _id
    Category.find({companyID: companyID}, {name: 1})
    .then((categories)=>{
        res.status(200).json({success: true, data: categories});
    })
    .catch((err)=>{//Caso algum erro ocorra
        res.status(404).json({success: false});
    });
  },

  findItemsByCategory: (req, res, next) =>{

    const categoryID = req.query.categoryID; //Parâmetro passado via GET

    //Procura todos itens associados a categoria
    Category.find({_id: categoryID}, {items: 1})
      .then((items)=>{
        res.status(200).json({success: true, data: items});
      })
      .catch((err)=>{//Caso algum erro ocorra
        res.status(404).json({success: false, err: err});
      });
  },

  newCategory:(req, res, next) =>{
    //Pegar dados da compania logada, via token
    const company = req.companyDecoded;

    //Cria uma nova categoria de acordo com o nome da categoria passada
    var newCategory = new Category({companyID: company._id, name: req.body.categoryName});
    newCategory.save().then((category)=>{//Caso a categoria seja criada com sucesso, retorna a categoria criada
        res.status(200).json({success: true, data: category});
    })
    .catch((err)=>{//Caso algum erro ocorra
        res.status(404).json({success: false, err: err});
    });
  },

  editCategory: (req, res, next)=>{
    //Pegar dados da compania logada, via token
    const company = req.companyDecoded;

    //Procura uma categoria pelo _id e altera seu nome (único atributo)
    //{new: true, upsert: false} - Retorna o objeto alterado e não cria um novo objeto caso não exista na busca
    Category.findOneAndUpdate({_id: req.body.categoryID}, {name: req.body.categoryName} ,{new: true, upsert: false})
      .then((category)=>{//Retorna o objeto alterado, em caso de sucesso na edição
          res.status(200).json({success: true, data: category});
      })
      .catch((err)=>{//Caso algum erro ocorra
          res.status(404).json({success: false, err: err});
      });
  },

  newItem: (req, res, next) =>{
    //Pegar dados da compania logada, via token
    const company = req.companyDecoded;

    //Encontra a categoria que irá receber um novo item
    Category.findOne({_id: req.body.categoryID})
      .then((category) =>{//Caso encontre uma categoria
        //FIXME Avaliar a necessidade do parse quando integrado com o AngularJS
        let itemPrices = req.body.itemPrices instanceof Array ? req.body.itemPrices : [req.body.itemPrices];
        itemPrices.forEach((data, index)=>{
          itemPrices[index] = JSON.parse(data);
        });


        //Adicionar o item no array de items da categoria
        category.items.push({name: req.body.itemName, description: req.body.itemDescription, prices: itemPrices});
        console.log(category);
        //Salvar categoria com as alterações realizadas anteriormente
         category.save().then(
          (categoryUpdated)=>{//Retorna todo objeto categoria alterado, em caso de sucesso na edição
            res.status(200).json({success: true, data: categoryUpdated});
          },
          (err)=>{//Caso algum erro ocorra na edição do objeto categoria
            res.status(404).json({success: false, err: err});
          }
        );
    })
    .catch((err) =>{//Caso algum erro ocorra na busca de uma categoria
        res.status(404).json({success: false, err: err});
    });

  },

  editItem: (req, res, next) =>{
    //Pegar dados da compania logada, via token
    const company = req.companyDecoded;

    //Busca o item que irá sofrer a edição
    Category.findOne({'_id': req.body.categoryID, 'items._id': req.body.itemID})
      .then((category) =>{
        //FIXME Avaliar a necessidade do parse quando integrado com o AngularJS
        let itemPrices = req.body.itemPrices instanceof Array ? req.body.itemPrices : [req.body.itemPrices];
        itemPrices.forEach((data, index)=>{
          itemPrices[index] = JSON.parse(data);
        });

        //Altera os dados do item selecionado
        //O item selecionado será retorna como único item no array de items da categoria
        category.items[0].name = req.body.itemName;
        category.items[0].description = req.body.itemDesciption;
        category.items[0].prices = itemPrices;

        //salva a categoria com as edições realizadas anteriormente
        category.save().then(
          (categoryUpdated)=>{//Retorna todo objeto categoria alterado, em caso de sucesso na edição
            res.status(200).json({success: true, data: categoryUpdated});
          },
          (errEdit)=>{//Caso algum erro ocorra na edição do objeto categoria
            res.status(404).json({success: false, err: errEdit});
          }
        )
      })
    .catch((err) =>{//Caso algum erro ocorra na busca de uma categoria
        res.status(404).json({success: false, err: err});
      }
    );

  },

  generateQRCode: (req, res, next) =>{
    //Pegar dados da compania logada, via token
    const companyDecoded = req.companyDecoded;

    Category.findOne({companyID: companyDecoded._id})
        .then((category)=>{//Gerar QR Code
          const qrCodePath = path.join(__dirname, '../public/qrCodes/', category.companyID+'.png');
          const code = qrCode.image(JSON.stringify({companyID: category.companyID}), {type: 'png', size: 10, margin: 0});
          const output = fs.createWriteStream(qrCodePath);
          code.pipe(output);
          //FIXME Apagar o qrcode após entregar o PDF ao usuário (economia de espaço)
        })
        .then((company)=>{//Gerar PDF com etiquetas
          const templatePath = path.join(__dirname, '../pdfTemplates/etiquetas.html');
          const templateHTML = fs.readFileSync(templatePath, 'utf8');
          const template = handlebars.compile(templateHTML); //Compila o template HTML usando Handlebars

          const data = {qrCode:'qrCodes/'+companyDecoded._id, infoImage: 'images/cardapio01-etiqueta'};
          const htmlResult = template(data); //Adiciona os dados necessários no template

          //Array do opçõs para geração do PDF
          const options = {
            "format": 'A4',
            "base": "file://"+path.join(__dirname, '../public/') //Define o caminho base para busca dos arquivos
          };

          const reportPath = path.join(__dirname, '../public/files/'+companyDecoded._id+'-etiquetas.pdf');
          //Criar o PDF com o HTML compilado com os dados
          htmlPDF.create(htmlResult, options).toFile(reportPath, (err, pdf)=>{
            if(err){
              return res.status(404).json({success: true, err:err});
            }
            //FIXME Encontrar uma forma de entregar o PDF ao usuário
            //FIXME Apagar o pdf após entregar ao usuário (economia de espaço)
            //Em caso de sucesso, retorna a url de acesso ao pdf
            return res.status(200).json({success:true, url: pdf});
          });
        })
        .catch((err)=>{//Caso algum erro aconteca na geração do PDF
          return res.status(404).json({success: false, err: err});
        });
  }
}

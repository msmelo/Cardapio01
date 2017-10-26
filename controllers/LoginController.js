const Company = require('../models/CompanyModel.js');
const config = require('../config/config.js');
const jwt = require('jsonwebtoken');
const cep = require('cep-promise');


module.exports = {
    //Cadastra uma nova empresa
    signup: (req, res, next) => {
        logger.debug('[Login Controller]', 'Parametros Signup', req.body);
        //TODO verificar dados já existente CNPJ, Email e razão social
        let newCompany = new Company(req.body);
        cep(req.body.zipcode).then((cepSuccess) => {
                logger.debug('[Login Controller]', 'CEP Recuperado', cepSuccess);
                newCompany.address.zipCode = cepSuccess.cep
                newCompany.address.street = cepSuccess.street
                newCompany.address.city = cepSuccess.city
                newCompany.address.state = cepSuccess.state
                newCompany.address.neighborhood = cepSuccess.neighborhood
                logger.debug('[Login Controller]', 'Salvar Empresa', newCompany);
                newCompany.save()
                    .then((company) => { //Usuário criado com sucesso
                        logger.debug('[Login Controller]', 'Empresa salva com sucesso');
                        logger.debug('[Login Controller]', 'Enviar email de boas vindas...');;
                        require('../lib/email/welcomeEmail.js')(req.body)
                            .then((result) => {
                                logger.debug('[Login Controller]', 'E-mail de boas-vindas enviado com sucesso.', result);
                                logger.debug('[Login Controller]', 'Gerar arquivo de tags...');
                                require('../lib/generateTags.js')(newCompany._id)
                                res.status(201).json({
                                    success: true,
                                    msg: "Empresa cadastrado com sucesso!"
                                }); //retorna o usuário criado
                            })
                    })
                    .catch((err) => { //Algum erro durante a criaçãos
                        logger.error('[Login Controller]', 'Erro ao cadastrar Empresa', err.errmsg);
                        res.status(202).json({
                            success: false,
                            msg: "Erro ao cadastrar nova empresa. Tente novamente!",
                            err: err.errmsg
                        });
                    });
            })
            .catch((err) => {
                console.log(err)
                res.status(200).json({})
            })
    },

    //Realiza o login da empresa no sistema admin
    login: (req, res, next) => {
        logger.debug('[Login Controller]', 'Parametros login', req.body);
        let fields = {
            email: 1,
            password: 1
        };
        Company.findOne({
                email: req.body.email
            }, fields)
            .then((company) => {
                logger.debug('[Login Controller]', 'Retorno dados da empresa', company.email);
                if (!company) { //Não foi encontrado companhia com o name passado
                    logger.debug('[Login Controller]', 'Não existe empresa com email fornecido');
                    res.status(500).json({
                        success: false,
                        token: null,
                        msg: 'A autenticação falhou. Empresa não encontrada!'
                    });
                } else {
                    logger.debug('[Login Controller]', 'Empresa encontrada. Verificar senha...');
                    company.comparePassword(req.body.password, (err, isMatch) => {
                        if (isMatch && !err) { //Caso a senha passada esteja correta
                            logger.debug('[Login Controller]', 'Senha correta. Gerar token...');
                            require('../lib/generateJWT.js')(company)
                                .then((success) => {
                                    logger.debug('[Login Controller]', 'Token gerado com sucesso', success);
                                    res.status(200).json(success);
                                })
                                .catch((err) => {
                                    logger.error('[Login Controller]', 'Erro ao gerar Token', err);
                                    err.msg = "Erro ao gerar token. Tente novamente!";
                                    res.status(500).json(err);
                                })
                        } else { //Senha não corresponde com a cadastrada
                            logger.error('[Login Controller]', 'Senha informada incorreta', err);
                            res.status(500).json({
                                success: false,
                                token: null,
                                msg: 'A autenticação falhou. Senha incorreta!'
                            })
                        }
                    });
                }
            })
            .catch((err) => { //Erro ao buscar usuário e/ou senha
                logger.error('[Login Controller]', 'Erro ao recuperar dados da empresa', err.errmsg);
                res.status(500).json({
                    success: false,
                    msg: 'A autenticação falhou. Erro ao recuperar dados da empresa.',
                    err: err.errmsg
                });
            });
    },

    //Realiza o logout da empresa do sistema admin
    logout: (req, res, next) => {
        logger.debug('[Login Controller]', 'Parametros logout', req.companyID);
        const companyID = req.companyID; //Recupera a empresa logada pelo token passado

        //Invalida o token cadastrado para a empresa.
        Company.update({
                _id: companyID
            }, {
                $set: {
                    accessToken: null
                }
            })
            .then((data) => {
                logger.debug('[Login Controller]', 'Token invalidado com sucesso', data);
                res.status(200).json({
                    success: true,
                    msg: "Logout realizado com sucesso!"
                });
            })
            .catch((err) => {
                logger.error('[Login Controller]', 'Erro ao invalidar token', err.errmsg);
                res.status(500).json({
                    success: false,
                    msg: "Falha ao realizar o Logout. Tente novamente!",
                    err: err.errmsg
                });
            });
    },

    tokenVerify: (req, res, next) => {
        logger.debug('[Login Controller]', 'TokenVerify no middleware JWTVerify');
        res.status(200).json({
            success: true,
            msg: "Token válido!"
        });
    },

    recoveryPass: (req, res, next) => {
        //@TODO Passar email e cnpj e corporateName
        logger.debug('[Login Controller]', 'Parametros para recuperar senha', req.body);
        const newPass = 'cardapio01';
        logger.debug('[Login Controller]', 'Nova senha gerada', newPass);
        Company.findOneAndUpdate({
                email: req.body.email,
                cnpj: req.body.cnpj,
                corporateName: req.body.corporateName
            }, {
                password: newPass
            })
            .then((companyMod) => {
                logger.debug('[Login Controller]', 'Senha temporária salva com sucesso');
                req.body.newPass = newPass;
                require('../lib/email/recoveryPassEmail.js')(req.body)
                    .then((result) => {
                        logger.debug('[Login Controller]', 'E-mail de recuperação de senha enviado com sucesso.', result);
                        res.status(200).json({
                            success: true,
                            msg: "Senha recuperada com sucesso. Verifique seu e-mail!"
                        });
                    })
                    .catch((errEmail) => {
                        logger.error('[Login Controller]', 'Erro ao enviar e-mail de recuperação de senha', errEmail);
                        res.status(200).json({
                            success: false,
                            msg: "Senha atualizada com sucesso! Erro ao enviar e-mail."
                        }); //retorna o usuário criado
                    })
            })
            .catch((err) => {
                logger.debug('[Login Controller]', 'Erro ao salvar senha temporária', err.errmsg);
                res.status(500).json({
                    success: false,
                    msg: "Erro ao buscar dados da empresa. Tente novamente!",
                    err: err.errmsg
                });
            })
    }
};

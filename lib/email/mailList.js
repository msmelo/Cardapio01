const config = require('../config/mailgun.js');
module.exports = (params) =>{

	logger.debug('[MailGun - MailList]', 'Parâmetros recebidos', params);
	const mailgun = require('mailgun-js')({apiKey: config.apiKey, domain: config.domain});
	const list = mailgun.lists(config.mailListCustomers);

	logger.debug('[MailGun - MailList]', 'Configurando parâmetros para adicionar e-mail na maillist');
	const data = {
	  subscribed: true,
	  address: req.email,
	  name: req.fantasyName
	};

	list.members().create(data, function (err, data) {
	  console.log(data);
	});

	logger.debug('[MailGun - MailList]', 'Enviando E-mail...');

	return mailgun.messages().send(data);

};
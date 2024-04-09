const io = require('socket.io')();
let users = [];

function getNameByID(Id) {
    for (const user of users) {
        if (user.id == Id) {
            return user.name;
        }
    }
}
function getIDByName(name) {
    for (const user of users) {
        if (user.name == name) {
            return user.id;
        }
    }
}

io.on('connection', (socket) => {
    console.log(socket.id + " connected");
    socket.on('CLIENT_SEND_USERNAME', function (data) {
        users.push({
            id: socket.id,
            name: data
        });
        io.emit('SERVER_SEND_JOIN', {
            message: data + " vua join vo phong",
            members: users
        });
    })
    socket.on('CLIENT_SEND_MESSAGE', function (data) {
        if (data.startsWith('/')) {
            let name = data.split(' ')[0];
            name  = name.substr(1,name.length);
            let message = data.substr(name.length+2,data.length);
            socket.to(getIDByName(name)).emit('SERVER_SEND_MESSAGE',{
                message: message,
                from: getNameByID(socket.id),
                to: name
            });
            socket.emit('SERVER_SEND_MESSAGE',{
                message: message,
                from: getNameByID(socket.id),
                to: name
            });

        } else {
            io.emit('SERVER_SEND_MESSAGE', {
                message: data,
                from: getNameByID(socket.id),
                to: 'All'
            }); 
        }
    })
    socket.on('disconnect', function () {
        let username;
        for (let index = 0; index < users.length; index++) {
            const element = users[index];
            if (element.id == socket.id) {
                username = element.name;
                users.splice(index, 1);
                break;
            }
        }
        io.emit('SERVER_SEND_DISCONNECT', {
            message: username+" da roi phong",
            members: users
        }); 
    })
});

module.exports = io;
const express = require('express');
const app = express();

const {Datastore} = require('@google-cloud/datastore');
const bodyParser = require('body-parser');

const projectId = 'belland-final-project';
const datastore = new Datastore({projectId:projectId});

const LOAD = "Load";
const BOAT = "Boat";

const PAGESIZE = 5;

const loadRouter = express.Router();
const boatRouter = express.Router();

app.use(bodyParser.json());

function fromDatastore(item){
    item.id = item[Datastore.KEY].id;
    return item;
}

/* ------------- Begin Load Model Functions ------------- */
function post_load(req, weight, content, delivery_date){
    var key = datastore.key(LOAD);

	const new_load = {"weight": weight, "content": content, "delivery_date": delivery_date, "carrier": null};
    return datastore.save({"key":key, "data":new_load}).then(() => {
        const self = `${req.protocol + '://' + req.get('host')}/loads/${key.id}`;
        new_load.self = self;
        return datastore.save({"key": key, "data": new_load}).then(() => {
            new_load.id = key.id;
            return new_load;
        })
    });
}

function get_loads(offset){
	const q = datastore.createQuery(LOAD).limit(PAGESIZE).offset(offset);
	return datastore.runQuery(q).then( (entities) => {
			return entities[0].map(fromDatastore);
		});
}

function get_load(id){
    const key = datastore.key([LOAD, parseInt(id,10)]);
    const query = datastore.createQuery(LOAD);
    const loadQuery = query.filter('__key__', key);
    return datastore.runQuery(loadQuery).then( (entities) => {
        return entities[0].map(fromDatastore)[0];
    });
}

function clean_load(id) {
    const key = datastore.key([LOAD, parseInt(id,10)]);

    return get_load(id).then((load) => {
        const cleaned_load = {"number": load.number, "current_boat": null, "self": load.self};
        return datastore.save({"key": key, "method": "update", "data": cleaned_load})
    })
}

function delete_load(id){
    const key = datastore.key([LOAD, parseInt(id,10)]);

    return get_load(id).then((load) => {
        if (load.carrier) {
            return delete_boat_load(load.carrier.id, id).then(() => {
                return datastore.delete(key);
            })
        } else {
            return datastore.delete(key);
        }
    })  
}

function delete_load_boat(id, boat_id) {
    const key = datastore.key([LOAD, parseInt(id,10)]);

    return get_load(id).then((load) => {
        edited_load = {"weight": load.weight, "content": load.content, "delivery_date": load.delivery_date, "carrier": null, "self": load.self};
        return datastore.save({"key": key, "method": "update", "data": edited_load}).then(() => {
            return {Code: 204};
        })
    })
}

/* ------------- End Model Functions ------------- */

/* ------------- Begin Boat Model Functions ------------- */
function post_boat(req, name, type, length){
    var key = datastore.key(BOAT);
    
    const new_boat = {"name": name, "type": type, "length": length, "loads": []};
	return datastore.save({"key":key, "data":new_boat}).then(() => {
        const self = `${req.protocol + '://' + req.get('host')}/boats/${key.id}`;
        new_boat.self = self;
        return datastore.save({"key": key, "data": new_boat}).then(() => {
            new_boat.id = key.id;
            return new_boat;
        })
    });
}

function get_boats(offset){
	const q = datastore.createQuery(BOAT).limit(PAGESIZE).offset(offset);
	return datastore.runQuery(q).then( (entities) => {
			return entities[0].map(fromDatastore);
		});
}

function get_boat(id){
    const key = datastore.key([BOAT, parseInt(id,10)]);
    const query = datastore.createQuery(BOAT);
    const boatQuery = query.filter('__key__', key);
    return datastore.runQuery(boatQuery).then( (entities) => {
        return entities[0].map(fromDatastore)[0];
    });
}

function get_boat_loads(id) {
    const key = datastore.key([BOAT, parseInt(id, 10)]);
    const query = datastore.createQuery(BOAT);
    const boatQuery = query.filter('__key__', key);
    return datastore.runQuery(boatQuery).then( (entities) => {
        return entities[0].map(fromDatastore)[0].loads;
    })
    .catch(() => {
        return {Error: "No boat with this boat_id exists"};
    }); 
}

function put_load_on_boat(boat_id, load_id){
    const boat_key = datastore.key([BOAT, parseInt(boat_id,10)]);
    const load_key = datastore.key([LOAD, parseInt(load_id,10)]);

    return get_boat(boat_id).then((boat) => {
        if (boat) {
            return get_load(load_id).then((load) => {
                if (load) {
                    if (load.carrier !== null) {
                        return {Code: 403, Error: "This load has already been assigned"}
                    } else {
                        // boat exists, can take load
                        load.carrier = {"id": boat_id, "name": boat.name, "self": boat.self};
                        return datastore.save({"key": load_key, "method": "update", "data": load}).then(() => {
                            boat.loads.push({"id": load.id, "self": load.self});
                            return datastore.save({"key": boat_key, "method": "update", "data": boat}).then(() => {
                                return {Code: 204};
                            });
                        })
                    }
                } else {
                    return {Code: 404, Error: "The specified boat and/or load does not exist"};
                }
            })
        } else {
            return {Code: 404, Error: "The specified boat and/or load does not exist"};
        }
    })
}

function put_boat(id, name, type, length){
    const key = datastore.key([BOAT, parseInt(id,10)]);
    const boat = {"name": name, "type": type, "length": length};
    return datastore.save({"key":key, "data":boat});
}

function delete_boat(id){
    const key = datastore.key([BOAT, parseInt(id,10)]);

    return get_boat(id).then((boat) => {
        if (boat.loads.length > 0) {
            const loads = boat.loads;
            const uncarriedLoads = [];
            loads.forEach(load => {
                uncarriedLoads.push(delete_load_boat(load.id));
            });

            return Promise.all(uncarriedLoads).then(() => {
                return datastore.delete(key);
            })
        } else {
            return datastore.delete(key);
        }
    });
}

function delete_boat_load(id, load_id) {
    return get_boat(id).then((boat) => {
        let loads = boat.loads;
        const load = loads.find(load => load.id == load_id);
        if (load !== undefined) {
            loads = loads.filter(load => load.id !== load_id);
            
            const key = datastore.key([BOAT, parseInt(id,10)]);
            const edited_boat = {"name": boat.name, "type": boat.type, "length": boat.length, "loads": loads, "self": boat.self};
            return datastore.save({"key":key, "data":edited_boat}).then(() => {
                return delete_load_boat(load_id, id);
            });
        } else {
            return {Code: 404, Error: "No load with this load_id is at the boat with this boat_id"}
        }
    })
};

/* ------------- End Model Functions ------------- */

/* ------------- Begin Load Controller Functions ------------- */

loadRouter.get('/', function(req, res){
    let offset = 0;
    if (req.params.offset) {
        offset = parseInt(req.params.offset, 10);
    }
    const loads = get_loads(offset)
	.then( (loads) => {
        const loadResponse = {data: loads}
        console.log(loads);
        loadResponse.next = `${req.secure ? "https" : "http"}://` + req.get('host') + `/loads?offset=${PAGESIZE + offset}`
        res.status(200).json(loadResponse);
    });
});

loadRouter.get('/:id', function(req, res){
    const load = get_load(req.params.id)
    .then( (load) => {
        if (load) {
            res.status(200).json(load);
        } else {
            res.status(404).send(JSON.stringify({Error: "No load with this load_id exists"}));
        }
    });
});

loadRouter.post('/', function(req, res){
    console.log(req.body);

    if (!req.body.weight || !req.body.content || !req.body.delivery_date) {
        res.status(400).send(JSON.stringify({Error: "The request object is missing at least one of the required attributes"}));
    }

    post_load(req, req.body.weight, req.body.content, req.body.delivery_date)
    .then( new_load => {res.status(201).send(JSON.stringify(new_load))} );
});

loadRouter.delete('/:id', function(req, res){
    const load = get_load(req.params.id)
    .then( (load) => {
        if (load) {
            delete_load(req.params.id).then(res.status(204).end())
        } else {
            res.status(404).send(JSON.stringify({Error: "No load with this load_id exists"}));
        }
    });    
});

loadRouter.delete('/:id/:boat', function(req, res){
    const load = delete_load_boat(req.params.id, req.params.boat)
    .then((val) => {
        if (val.Code === 204) {
            res.status(204).send();
        } else if (val.Code === 403) {
            res.status(403).send(val);
        } else if (val.Code === 404) {
            res.status(404).send(val);
        }
    });   
});

/* ------------- End Controller Functions ------------- */

/* ------------- Begin Boat Controller Functions ------------- */
boatRouter.get('/', function(req, res){
    let offset = 0;
    if (req.params.offset) {
        offset = parseInt(req.params.offset, 10);
    }
    const boats = get_boats(offset)
	.then( (boats) => {
        const boatResponse = {data: boats}
        boatResponse.next = `${req.secure ? "https" : "http"}://` + req.get('host') + `/boats?offset=${PAGESIZE + offset}`
        res.status(200).json(boatResponse);
    });
});

boatRouter.get('/:id', function(req, res){
    const boat = get_boat(req.params.id)
    .then( (boat) => {
        if (boat) {
            res.status(200).json(boat);
        } else {
            res.status(404).send(JSON.stringify({Error: "No boat with this boat_id exists"}));
        }
    });
});

boatRouter.get('/:id/loads', function(req, res) {
    const boat = get_boat_loads(req.params.id)
    .then((val) => {
        if (val.Error) {
            res.status(404).send(JSON.stringify({Error: "No boat with this boat_id exists"}));
        } else if (val) {
            res.status(200).json(val);
        }
    })
});

boatRouter.post('/', function(req, res){
    console.log(req.body);

    if (!req.body.name || !req.body.type || !req.body.length) {
        res.status(400).send(JSON.stringify({Error: "The request object is missing at least one of the required attributes"}));
    }

    post_boat(req, req.body.name, req.body.type, req.body.length)
    .then( new_boat => {res.status(201).send(JSON.stringify(new_boat))} );
});

boatRouter.patch('/:id', function(req, res) {
    if (!req.body.name || !req.body.type || !req.body.length) {
        res.status(400).send(JSON.stringify({Error: "The request object is missing at least one of the required attributes"}));
    }

    patch_boat(req.params.id, req.body.name, req.body.type, req.body.length)
    .then(val => {
        if (val.Error) {
            res.status(404).send(val);
        } else {
            res.status(200).json(val);
        }
    })
});

boatRouter.put('/:id', function(req, res){
    put_boat(req.params.id, req.body.name, req.body.type, req.body.length)
    .then(res.status(200));
});

boatRouter.put('/:id/loads/:load_id', function(req, res){
    put_load_on_boat(req.params.id, req.params.load_id)
    .then((val) => {
        if (val.Code === 204) {
            res.status(204).send();
        } else if (val.Code === 403) {
            res.status(403).send(val);
        } else if (val.Code === 404) {
            res.status(404).send(val);
        }
    });
});

boatRouter.delete('/:id', function(req, res){
    const boat = get_boat(req.params.id)
    .then( (boat) => {
        if (boat) {
            delete_boat(req.params.id).then(res.status(204).end())
        } else {
            res.status(404).send(JSON.stringify({Error: "No boat with this boat_id exists"}));
        }
    });
});

boatRouter.delete('/:id/loads/:load_id', function (req, res) {
    const load = get_load(req.params.load_id)
    .then((load) => {
        if (!load) {
            res.status(404).send(JSON.stringify({Error: "No load with this load_id is at the boat with this boat_id"}));
        }
    })
    const boat = get_boat(req.params.id)
    .then( (boat) => {
        if (boat) {
            delete_boat_load(req.params.id, req.params.load_id)
            .then((val) => {
                if (val.Error) {
                    res.status(val.Code).send(val);
                } else {
                    res.status(val.Code).send();
                }
            })
        } else {
            res.status(404).send(JSON.stringify({Error: "No load with this load_id is at the boat with this boat_id"}));
        }
    });
});

/* ------------- End Controller Functions ------------- */

app.use('/loads', loadRouter);
app.use('/boats', boatRouter);

// Listen to the App Engine-specified port, or 8080 otherwise
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}...`);
});
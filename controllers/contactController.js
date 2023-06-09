const asyncHandler = require("express-async-handler")
const Contact = require('../models/contactModel');
const contactModel = require("../models/contactModel");

//@des Get all contacts
//@route GET /api/contacts
//@access private 
const getContacts = asyncHandler(async (req, res) => {
    const contacts = await Contact.find({ user_id: req.user.id });
    res.status(200).json(contacts);
})

//@des Create new contacts
//@route POST /api/contacts
//@access private 
const createContact = asyncHandler(async (req, res) => {
    console.log("The request body is :", req.body);
    const { name, email, phone } = req.body;
    if (!name || !email || !phone) {
        res.status(400);
        throw new Error("All fields are Mandatory")
    }
    const contact = await contactModel.create({
        name,
        email,
        phone,
        user_id: req.user.id
    })
    res.status(201).json(contact);
})

//@des Get a specific contact
//@route GET /api/contacts:id
//@access private 
const getContact = asyncHandler(async (req, res) => {
    const contact = await Contact.findById(req.params.id);
    if (!contact) {
        res.status(404);
        throw new Error("Contact not found");
    }
    res.status(200).json(contact);
})

//@des Update contacts
//@route POST /api/contacts/:id
//@access private 
const updateContact = asyncHandler(async (req, res) => {
    const contact = await Contact.findById(req.params.id);
    if (!contact) {
        res.status(404);
        throw new Error("Contact not found");
    }

    const updatedContact = await Contact.findByIdAndUpdate(
        req.params.id,
        req.body,
        { new: true }
    );

    res.status(200).json(updatedContact);
})

//@des Delete contacts
//@route DELETE /api/contacts/:id
//@access private 
const deleteContact = asyncHandler(async (req, res) => {
    const contact = await Contact.findById(req.params.id);
    if (!contact) {
        res.status(404);
        throw new Error("Contact not found");
    }
    await Contact.findOneAndRemove()
    res.status(200).json(contact);
})

module.exports = {
    getContacts,
    getContact,
    createContact,
    updateContact,
    deleteContact
}

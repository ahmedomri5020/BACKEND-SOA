package com.ahmed.pays.service;

import java.util.List;

import com.ahmed.pays.repo.ImageRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ahmed.pays.entities.Pays;
import com.ahmed.pays.entities.Plat;
import com.ahmed.pays.repo.PlatRepository;

@Service
public class PlatServiceImpl implements PlatService {

    @Autowired
    PlatRepository platRepository;
    @Autowired
    ImageRepository imageRepository;

    @Override
    public Plat savePlat(Plat p) {
        return platRepository.save(p);
    }

    @Override
    public Plat updatePlat(Plat p)  {
        //Long oldProdImageId = this.getPlat(p.getIdPlat()).getImage().getIdImage();
        //Long newProdImageId = p.getImage().getIdImage();

        Plat platUpdated = platRepository.save(p);

      //if (oldProdImageId != newProdImageId)
      //      imageRepository.deleteById(oldProdImageId);

        return platUpdated;
    }

    @Override
    public void deletePlat(Plat p) {
        platRepository.delete(p);
    }

    @Override
    public void deletePlatById(Long id) {
        platRepository.deleteById(id);
    }

    @Override
    public Plat getPlat(Long id) {
        return platRepository.findById(id).orElse(null);
    }

    @Override
    public List<Plat> getAllPlats() {
        return platRepository.findAll();
    }

    @Override
    public List<Plat> findByNomPlat(String nom) {
        return platRepository.findByNomPlat(nom);
    }

    @Override
    public List<Plat> findByNomPlatContains(String nom) {
        return platRepository.findByNomPlatContains(nom);
    }

    @Override
    public List<Plat> findByNomPrix(String nom, Double prix) {
        return platRepository.findByNomPrix(nom, prix);
    }

    @Override
    public List<Plat> findByPays(Pays pays) {
        return platRepository.findByPays(pays);
    }
    
    @Override
    public List<Plat> findByPaysIdPays(Long idPays) {
        return platRepository.findByPaysIdPays(idPays);
    }
    
	@Override
	public List<Plat> findByOrderByNomPlatAsc() {
		return platRepository.findByOrderByNomPlatAsc();
	}

    @Override
    public List<Plat> trierPlatsNomsPrix() {
        return platRepository.trierPlatsNomsPrix();
    }






}
package com.ahmed.pays.service;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import com.ahmed.pays.entities.Plat;
import com.ahmed.pays.repo.PlatRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import com.ahmed.pays.entities.Image;
import com.ahmed.pays.repo.ImageRepository;


@Service
public class ImageServiceImpl implements ImageService{

    @Autowired
    ImageRepository imageRepository;
    @Autowired
    PlatService platService;
    @Autowired
    PlatRepository platRepository;

    @Override
    public Image uplaodImage(MultipartFile file) throws IOException {
        // Save the image to the database
        Image image = imageRepository.save(Image.builder()
                .name(file.getOriginalFilename())
                .type(file.getContentType())
                .image(file.getBytes())
                .build());

        // Now associate the image with the Plat (product)
        // This part should be handled in PlatService if necessary
        return image;
    }

    @Override
    public Image getImageDetails(Long id) throws IOException{
        final Optional<Image> dbImage = imageRepository. findById (id);

        return Image.builder()
                .idImage(dbImage.get().getIdImage())
                .name(dbImage.get().getName())
                .type(dbImage.get().getType())
                .image(dbImage.get().getImage()).build() ;
    }

    @Override
    public ResponseEntity<byte[]> getImage(Long id) throws IOException{
        final Optional<Image> dbImage = imageRepository. findById (id);

        return ResponseEntity
                .ok()
                .contentType(MediaType.valueOf(dbImage.get().getType()))
                .body(dbImage.get().getImage());
    }

    @Override
    public void deleteImage(Long id) {
        imageRepository.deleteById(id);
    }
    @Override
    public Image uplaodImagePlat(MultipartFile file,Long idPlat)
            throws IOException {
        Plat p = new Plat();
        p.setIdPlat(idPlat);
        return imageRepository.save(Image.builder()
                .name(file.getOriginalFilename())
                .type(file.getContentType())
                .image(file.getBytes())
                .plat(p).build() );
    }
    @Override
    public List<Image> getImagesParPlat(Long prodId) {
        Plat p = platRepository.findById(prodId).get();
        return p.getImages();
    }

}